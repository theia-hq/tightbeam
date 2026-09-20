use core::marker::PhantomData;

use bifrost::{
    Announced, Error, InProcess, NodeId, PeerProof, Refusal, RefusalDetail, Sealed,
    SecurityProfile, Session,
};

use crate::protocol::{Request, RequestReadError, RequestWriteError, Response};
use crate::security::TransportInsecure;

/// A session used only for its declared profile: [`Request::write_checked`] reads the type, never a
/// value, so these stand-ins never get called and their methods answer with a closed stream.
struct StubSession<P>(PhantomData<P>);

impl<P: SecurityProfile> Session for StubSession<P> {
    type Security = P;
    type Write = Vec<u8>;
    type Read = &'static [u8];

    fn peer(&self) -> NodeId {
        NodeId::from_ed25519_secret(&[0u8; 32])
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        Err(Error::Closed)
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        Err(Error::Closed)
    }

    async fn wait_closed(&self) {}
}

/// A credential-bearing request: a capability link in slot 1.
fn presenting() -> Request {
    Request {
        service: "svc".to_owned(),
        capability: Some("sheer:bf01abc.def".to_owned()),
        membership: None,
    }
}

#[tokio::test]
async fn request_roundtrips_without_a_capability() {
    let request = Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.unwrap();
    assert_eq!(Request::read(&mut buf.as_slice()).await.unwrap(), request);
}

#[tokio::test]
async fn request_roundtrips_with_a_capability() {
    let request = Request {
        service: "svc".to_owned(),
        capability: Some("sheer:bf01abc.def".to_owned()),
        membership: None,
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.unwrap();
    assert_eq!(Request::read(&mut buf.as_slice()).await.unwrap(), request);
}

#[tokio::test]
async fn request_roundtrips_with_both_slots() {
    // TB03 added this second slot: a signet-bound dial carries slot 1 (the slip) AND slot 2 (a badge under
    // the foreign fleet). Both present must round-trip byte-for-byte, so the gate reads the same two tokens
    // the dialer wrote.
    let request = Request {
        service: "ssh".to_owned(),
        capability: Some("sheer:bf01abc.def".to_owned()),
        membership: Some("sheer:bf02ghi.jkl".to_owned()),
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.unwrap();
    assert_eq!(Request::read(&mut buf.as_slice()).await.unwrap(), request);
}

#[tokio::test]
async fn response_roundtrips() {
    // Every refusal variant round-trips: the payload-free `NotAdmitted` and both bounded-detail
    // variants, so a host can only write a frame its own reader reconstructs.
    for response in [
        Response::Ok,
        Response::Refused(Refusal::NotAdmitted),
        Response::Refused(Refusal::BadRequest {
            detail: RefusalDetail::bounded("unknown service"),
        }),
        Response::Refused(Refusal::Unavailable {
            detail: RefusalDetail::bounded("no handler"),
        }),
    ] {
        let mut buf = Vec::new();
        response.write(&mut buf).await.unwrap();
        assert_eq!(Response::read(&mut buf.as_slice()).await.unwrap(), response);
    }
}

#[tokio::test]
async fn rejects_foreign_stream() {
    let mut buf = b"XXXXnonsense".as_slice();
    let error = Request::read(&mut buf)
        .await
        .expect_err("a foreign identity is not a tightbeam stream");
    // A foreign protocol is told nothing: we have no idea what would be meaningful to it, and silence
    // keeps this path from being a better fingerprint than the session handshake already is.
    assert!(
        error.refusal().is_none(),
        "a foreign stream gets no wire answer, only a host log line"
    );
    assert!(matches!(error, RequestReadError::Foreign));
}

/// The version half of the magic is PARSED, so a tightbeam peer on another rev is a distinguishable
/// condition with a wire answer, not a foreign stream. Revert the parse to a four-byte comparison and
/// this goes red at the first assertion.
#[tokio::test]
async fn a_version_mismatch_is_not_a_foreign_stream() {
    let mut buf = Vec::new();
    Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut buf)
    .await
    .unwrap();
    // One well-formed request, one digit of the version changed: the only difference between this and
    // the frame the host speaks.
    buf[3] = b'5';

    let error = Request::read(&mut buf.as_slice())
        .await
        .expect_err("TB05 is not this build's grammar");
    assert!(
        !matches!(error, RequestReadError::Foreign),
        "a tightbeam peer on another rev is not a foreign protocol"
    );
    let refusal = error
        .refusal()
        .expect("a version mismatch is answerable on the wire");
    let Refusal::BadRequest { detail } = &refusal else {
        panic!("a version mismatch is the peer's grammar, so it is a bad request: {refusal:?}");
    };
    // Both versions, so the dialer learns what it speaks AND what the host speaks; one of them alone
    // leaves them guessing at the other.
    assert!(detail.as_str().contains("TB05"), "{detail}");
    assert!(detail.as_str().contains("TB04"), "{detail}");
}

/// The detail is a wire surface, so it must fit the cap even on the worst input: the version half is two
/// arbitrary peer-controlled bytes, and escaping expands each one.
#[tokio::test]
async fn a_version_refusal_detail_fits_the_wire_cap() {
    let mut buf = Vec::new();
    Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut buf)
    .await
    .unwrap();
    buf[2..4].copy_from_slice(&[0xff, 0xff]);

    let error = Request::read(&mut buf.as_slice())
        .await
        .expect_err("unprintable version bytes are still a version");
    let Some(Refusal::BadRequest { detail }) = error.refusal() else {
        panic!("a version mismatch is answerable whatever the bytes say");
    };
    assert!(detail.as_str().len() <= RefusalDetail::MAX_LEN, "{detail}");
}

/// A head from the neighbouring `TBH1` wire gets NOTHING back. Its identity is the maximal leading run
/// of capitals, `TBH`, which is not `TB`, so it is a foreign wire and every foreign wire is owed
/// silence. Compare a fixed two bytes instead of the run and this goes red: the host reads the head as
/// `TB` plus version `H1` and answers a peer that does not speak this wire with this host's version.
///
/// The assertion is over the octets a host would put on the stream, not over the absence of a refusal
/// value, because "there is nothing to say" is only proved by there being nothing to write.
#[tokio::test]
async fn a_neighbouring_identity_gets_no_octets() {
    let mut head = Vec::new();
    Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut head)
    .await
    .unwrap();
    // A well-formed body behind another wire's magic: the four magic bytes are the only difference
    // between this head and one this host serves.
    head[..4].copy_from_slice(b"TBH1");

    let error = Request::read(&mut head.as_slice())
        .await
        .expect_err("TBH1 is not this wire");
    let mut answer = Vec::new();
    if let Some(refusal) = error.refusal() {
        Response::Refused(refusal).write(&mut answer).await.unwrap();
    }
    assert!(
        answer.is_empty(),
        "a foreign wire gets zero octets, this host wrote {answer:02x?}"
    );
    assert!(matches!(error, RequestReadError::Foreign));
}

/// The checked writer refuses a credential over an announced session BEFORE any byte: the writer stays
/// empty and the typed refusal names the declared profile.
#[tokio::test]
async fn a_credential_write_over_an_announced_session_refuses_before_any_byte() {
    let mut writer = Vec::new();
    let error = presenting()
        .write_checked::<StubSession<Announced>, _>(&mut writer)
        .await
        .expect_err("an announced profile must refuse a credential");
    assert!(matches!(
        error,
        RequestWriteError::Insecure(TransportInsecure {
            declared: PeerProof::Announced
        })
    ));
    assert!(
        writer.is_empty(),
        "no byte may be written before the refusal"
    );
}

/// A membership badge is a credential too: slot 2 alone is refused over an announced session.
#[tokio::test]
async fn a_membership_write_over_an_announced_session_refuses() {
    let request = Request {
        service: "svc".to_owned(),
        capability: None,
        membership: Some("sheer:bf02ghi.jkl".to_owned()),
    };
    let mut writer = Vec::new();
    assert!(
        request
            .write_checked::<StubSession<Announced>, _>(&mut writer)
            .await
            .is_err()
    );
    assert!(
        writer.is_empty(),
        "no byte may be written before the refusal"
    );
}

/// A credential over either proven profile writes the frame unchanged: the bytes the raw `write` emits.
#[tokio::test]
async fn a_credential_write_over_a_proven_session_writes() {
    let request = presenting();

    let mut sealed = Vec::new();
    request
        .write_checked::<StubSession<Sealed>, _>(&mut sealed)
        .await
        .expect("sealed proves the peer");
    assert_eq!(
        Request::read(&mut sealed.as_slice()).await.unwrap(),
        request
    );

    let mut in_process = Vec::new();
    request
        .write_checked::<StubSession<InProcess>, _>(&mut in_process)
        .await
        .expect("in-process proves the peer");
    assert_eq!(
        Request::read(&mut in_process.as_slice()).await.unwrap(),
        request
    );
}

/// A request with no credential is not a credential path: it writes over any profile, announced included.
#[tokio::test]
async fn a_tokenless_write_over_an_announced_session_writes() {
    let request = Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    };
    let mut writer = Vec::new();
    request
        .write_checked::<StubSession<Announced>, _>(&mut writer)
        .await
        .expect("no credential, no refusal");
    assert_eq!(
        Request::read(&mut writer.as_slice()).await.unwrap(),
        request
    );
}

/// The wire vectors `PROTOCOL.md` publishes.
///
/// Every octet in that document is produced HERE, by this crate's own codec, and the document is read
/// back and compared. A specification whose vectors are typed by hand is a second implementation nobody
/// runs; these cannot drift, because the wire moving turns the drift into a failing test.
///
/// To regenerate after a wire change, run the module and paste the printed blocks over the ones in the
/// document:
///
/// ```text
/// cargo test -p tightbeam --lib protocol_tests::vectors -- --nocapture
/// ```
mod vectors {
    use std::collections::BTreeMap;

    use bifrost::{Refusal, RefusalDetail};

    use crate::protocol::{Request, Response};

    /// The document under test, compiled in, so `cargo test` and the published specification cannot be
    /// two different files.
    const PROTOCOL_MD: &str = include_str!("../PROTOCOL.md");

    /// One published vector: the label the document files it under, and the octets that belong under it.
    struct Vector {
        name: &'static str,
        bytes: Vec<u8>,
    }

    /// Encode a request and prove the reader takes those exact octets back to the same value. A vector is
    /// only a vector when both halves of the codec agree on it, so the round trip is part of building one
    /// rather than a separate test that could be forgotten.
    async fn request_vector(name: &'static str, request: Request) -> Vector {
        let mut bytes = Vec::new();
        request.write(&mut bytes).await.expect("a Vec never fails");
        assert_eq!(
            Request::read(&mut bytes.as_slice()).await.unwrap(),
            request,
            "{name} does not read back"
        );
        Vector { name, bytes }
    }

    /// The same for a response frame.
    async fn response_vector(name: &'static str, response: Response) -> Vector {
        let mut bytes = Vec::new();
        response.write(&mut bytes).await.expect("a Vec never fails");
        assert_eq!(
            Response::read(&mut bytes.as_slice()).await.unwrap(),
            response,
            "{name} does not read back"
        );
        Vector { name, bytes }
    }

    /// A peer's opening octets, built by writing a well-formed minimal request and overwriting the four
    /// magic bytes with `magic`. Built rather than typed so the body after the magic is exactly the body
    /// every other vector uses, leaving the magic as the only difference under test.
    async fn head_vector(name: &'static str, magic: &[u8; 4]) -> Vector {
        let mut bytes = Vec::new();
        minimal()
            .write(&mut bytes)
            .await
            .expect("a Vec never fails");
        bytes[..4].copy_from_slice(magic);
        Vector { name, bytes }
    }

    /// The request every head vector carries after its magic, and the minimal request in its own right:
    /// one service name, neither credential slot filled.
    fn minimal() -> Request {
        Request {
            service: "ssh".to_owned(),
            capability: None,
            membership: None,
        }
    }

    /// The answer a host writes to `head`, which is a refusal exactly when the head named this
    /// protocol's identity and a version the host does not serve, and nothing at all otherwise.
    async fn answer_to(mut head: &[u8]) -> Option<Refusal> {
        Request::read(&mut head)
            .await
            .expect_err("every head here is one this build cannot read")
            .refusal()
    }

    /// Every vector the document publishes, in document order.
    async fn published() -> Vec<Vector> {
        let mismatch = head_vector("tb04-head-version-mismatch", b"TB05").await;
        let neighbour = head_vector("tb04-head-neighbouring-identity", b"TBH1").await;
        let foreign = head_vector("tb04-head-foreign", b"SSH-").await;
        assert!(
            answer_to(&foreign.bytes).await.is_none(),
            "a foreign identity gets no octets back"
        );
        assert!(
            answer_to(&neighbour.bytes).await.is_none(),
            "a neighbouring identity is a foreign wire, so it gets no octets back either"
        );
        let mismatch_answer = answer_to(&mismatch.bytes)
            .await
            .expect("a served identity on an unserved version is answered");
        vec![
            request_vector("tb04-request-minimal", minimal()).await,
            request_vector(
                "tb04-request-capability-and-membership",
                Request {
                    service: "ssh".to_owned(),
                    capability: Some("sheer:bf01abc.def".to_owned()),
                    membership: Some("sheer:bf02ghi.jkl".to_owned()),
                },
            )
            .await,
            response_vector("tb04-response-ok", Response::Ok).await,
            response_vector(
                "tb04-response-not-admitted",
                Response::Refused(Refusal::NotAdmitted),
            )
            .await,
            // The host's own prose for a service name that is not a name, restated here because the
            // wording lives inline at the site that writes it. The vector fixes the FRAMING; a peer
            // never parses the text.
            response_vector(
                "tb04-response-bad-request-service-name",
                Response::Refused(Refusal::BadRequest {
                    detail: RefusalDetail::bounded(format!(
                        "invalid service name {:?}",
                        "ssh admin"
                    )),
                }),
            )
            .await,
            // Likewise fixed text: the one pre-admission `Unavailable` a host writes, when its gate ran
            // out of time and so ruled on nothing.
            response_vector(
                "tb04-response-unavailable",
                Response::Refused(Refusal::Unavailable {
                    detail: RefusalDetail::bounded(
                        "the gate did not finish deciding in time; retry",
                    ),
                }),
            )
            .await,
            mismatch,
            response_vector(
                "tb04-response-bad-request-version-mismatch",
                Response::Refused(mismatch_answer),
            )
            .await,
            foreign,
            neighbour,
        ]
    }

    /// The octets as one unbroken lowercase hex string: the form the document is compared in, so the
    /// grouping and line breaks a reader sees are presentation and nothing more.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The octets as the document shows them: lowercase pairs, sixteen to a line, so a regenerated block
    /// pastes in unedited.
    fn octet_lines(bytes: &[u8]) -> String {
        bytes
            .chunks(16)
            .map(|chunk| {
                chunk
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The vectors the document publishes, parsed out of it: a block opens with a `vector <name>` line,
    /// and the octet lines under it, to the next blank line or fence, are the frame. Reading the document
    /// rather than restating it is what makes a divergence a test failure instead of a discovery.
    fn documented() -> BTreeMap<String, String> {
        let mut found = BTreeMap::new();
        let mut lines = PROTOCOL_MD.lines();
        while let Some(line) = lines.next() {
            let Some(name) = line.trim().strip_prefix("vector ") else {
                continue;
            };
            let mut octets = String::new();
            for line in lines.by_ref() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("```") {
                    break;
                }
                octets.extend(line.chars().filter(|char| !char.is_whitespace()));
            }
            assert!(
                found.insert(name.trim().to_owned(), octets).is_none(),
                "{name} is published twice"
            );
        }
        found
    }

    /// Every octet the document publishes is an octet this codec writes, and every vector it names is one
    /// the codec still produces. Both directions: a stale vector and an orphaned one are the same defect.
    #[tokio::test]
    async fn the_document_publishes_exactly_what_this_codec_writes() {
        let mut documented = documented();
        let mut wrong = Vec::new();
        for Vector { name, bytes } in published().await {
            // Printed unconditionally: this is the regeneration output, and a run with --nocapture is
            // how the document is rewritten after the wire moves.
            println!("vector {name}\n{}\n", octet_lines(&bytes));
            let expected = hex(&bytes);
            match documented.remove(name) {
                Some(published) if published == expected => {}
                Some(published) => {
                    wrong.push(format!("{name}: published {published}, wire {expected}"))
                }
                None => wrong.push(format!("{name}: not published; wire {expected}")),
            }
        }
        for orphan in documented.keys() {
            wrong.push(format!(
                "{orphan}: published, but this codec writes no such frame"
            ));
        }
        assert!(
            wrong.is_empty(),
            "PROTOCOL.md is out of date:\n{}",
            wrong.join("\n")
        );
    }
}
