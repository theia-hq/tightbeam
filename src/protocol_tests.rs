use core::marker::PhantomData;

use bifrost::{
    Announced, Error, InProcess, NodeId, PeerProof, Refusal, RefusalDetail, Sealed,
    SecurityProfile, Session,
};

use crate::protocol::{Request, RequestWriteError, Response};
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
    assert!(Request::read(&mut buf).await.is_err());
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
