//! Tests for admission: the per-service ruling, the public-path caps, the live enable/disable oracle, the
//! member floor, and the one uniform refusal every miss gets on the wire.

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;

use bifrost::{
    Announced, ChannelProtection, NoDiscovery, Node, NodeId, PeerProof, Refusal, Security, Session,
};
use bifrost_mem::MemTransport;
use nauthy::{Gate, Service};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Semaphore;

use super::{Admission, FIRST_TRAFFIC_TIMEOUT, resolve_single_service, serve_request};
use crate::enabled::AllEnabled;
use crate::open_policy::OptIn;
use crate::tunnel::exposer::{
    PUBLIC_STREAM_PERMITS, PublicPool, PublicSession, RAW_STREAM_OPEN_PERMITS, SessionPeer,
    serve_session,
};
use crate::tunnel::fixtures::{
    GatedNoop, OpenNoop, ServiceStream, family_gate, prove, services, svc,
};
use crate::tunnel::router::{PublicRequest, PublicServices, PublicUnsafeRequest, Services};
use crate::tunnel::{BoxRead, BoxWrite, CancellationToken, Handler, ServeError, Served};

/// A public handler that parks inside `serve` until a permit is added to `release`, so a
/// public-stream cap test can hold one stream's permit deterministically. `entered` signals the test
/// that the serve body is running, which is after the stream was admitted and its permit taken.
struct Parked {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<Semaphore>,
}
impl Handler for Parked {
    type Exposure = OptIn;
    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        self.entered.notify_one();
        let _permit = self.release.acquire().await;
        Ok(())
    }
}

/// Make a named FIFO with no writer, so opening it for read BLOCKS (the parking a flood exploits). The
/// path is unique per process + a counter so parallel tests never collide; the caller removes it.
fn never_written_fifo(tag: &str) -> std::path::PathBuf {
    use core::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "tightbeam-fifo-cap-{}-{tag}-{}",
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_file(&path);
    let mut c_path = path.clone().into_os_string().into_encoded_bytes();
    c_path.push(0);
    // SAFETY: `c_path` is a NUL-terminated C string that outlives the call; a failed mkfifo returns -1
    // and the test fails on it. Mode 0600: the FIFO is scratch, readable/writable by this process only.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr().cast::<libc::c_char>(), 0o600) };
    assert_eq!(rc, 0, "mkfifo {} failed", path.display());
    path
}

/// A `Serving` context over `services` sharing one `permits` pool, on a `Gate::Open` base with empty
/// public overlays and an empty registry: the shared node state the raw-stream cap tests drive many
/// `serve_request`s against.
fn open_serving(services: Services, permits: Semaphore) -> std::sync::Arc<super::Serving> {
    std::sync::Arc::new(super::Serving {
        gate: Gate::Open,
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services,
        raw_stream_opens: permits,
        public_pool: PublicPool::new(),
        enabled: Box::new(AllEnabled),
        cuts: None,
    })
}

/// The declared security the admission-core tests present by default: proven and sealed, what a real
/// handshake-backed transport declares. The announced-refusal test passes its own.
const PROVEN: Security = Security {
    peer: PeerProof::Proven,
    channel: ChannelProtection::Aead,
};

/// Drive one `serve_request` for `service` against the shared `serving` context, with a fresh public
/// session and no token: the common shape, for tests that do not need to hold the session open or
/// present a capability. See [`drive_open_in`] for that.
fn drive_open(
    service: &str,
    serving: std::sync::Arc<super::Serving>,
) -> (
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    impl core::future::Future<Output = eyre::Result<()>>,
) {
    drive_open_in(
        service,
        serving,
        std::sync::Arc::new(PublicSession::default()),
        None,
    )
}

/// Drive one `serve_request` for `service` against the shared `serving` context under `session`, and
/// return the client's stream end plus the serving future. The serving future is returned un-awaited so
/// a caller can let it park (a never-written FIFO, a parked handler) or poll it for the refusal, and the
/// returned reader carries the host's `Response`. Uses `tokio::io::duplex` so no transport is needed.
/// The session is passed by `Arc` because the caller may hold it open (the public-session cap test) and
/// a spawned future must stay `'static`; `capability` lets a test dial as a member.
fn drive_open_in(
    service: &str,
    serving: std::sync::Arc<super::Serving>,
    session: std::sync::Arc<PublicSession>,
    capability: Option<String>,
) -> (
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    impl core::future::Future<Output = eyre::Result<()>>,
) {
    let (client, server) = tokio::io::duplex(1024);
    let (server_read, server_write) = tokio::io::split(server);
    let (client_read, mut client_write) = tokio::io::split(client);
    let service = service.to_owned();
    // The peer id is only for the host's log line here; any valid NodeId does.
    let peer = SessionPeer {
        node: bifrost::NodeId::from_ed25519_secret(&[9u8; 32]),
        security: PROVEN,
    };
    let serve = async move {
        crate::protocol::Request {
            service: service.clone(),
            capability,
            membership: None,
        }
        .write(&mut client_write)
        .await
        .expect("write request");
        // Close the client's write half now the request is sent: the served splice's downstream copy
        // (peer -> `io::sink()`) ends on this EOF, so a served stream can actually finish (otherwise the
        // splice's `try_join!` would wait forever for the client to hang up).
        drop(client_write);
        serve_request(peer, server_write, server_read, serving, session, None).await
    };
    (client_read, serve)
}

/// Drive one `serve_request` against `serving` over a hand-built opening frame, returning the client's
/// read half plus the serving future. Writing the bytes verbatim is the only way to present a preamble
/// this build cannot write, which is what a peer on another rev is.
fn drive_frame(
    frame: Vec<u8>,
    serving: std::sync::Arc<super::Serving>,
) -> (
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    impl core::future::Future<Output = eyre::Result<()>>,
) {
    let (client, server) = tokio::io::duplex(1024);
    let (server_read, server_write) = tokio::io::split(server);
    let (client_read, mut client_write) = tokio::io::split(client);
    let peer = SessionPeer {
        node: bifrost::NodeId::from_ed25519_secret(&[9u8; 32]),
        security: PROVEN,
    };
    let serve = async move {
        tokio::io::AsyncWriteExt::write_all(&mut client_write, &frame)
            .await
            .expect("write frame");
        drop(client_write);
        serve_request(
            peer,
            server_write,
            server_read,
            serving,
            std::sync::Arc::new(PublicSession::default()),
            None,
        )
        .await
    };
    (client_read, serve)
}

/// One well-formed request with its four magic bytes replaced. Everything after the preamble is exactly
/// what this build writes, so the only thing under test is how the magic is READ.
async fn frame_with_magic(magic: &[u8; 4]) -> Vec<u8> {
    let mut frame = Vec::new();
    crate::protocol::Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut frame)
    .await
    .expect("write request");
    frame[..4].copy_from_slice(magic);
    frame
}

/// A node with one ordinary service, for the preamble tests: the refusal lands before dispatch, so what
/// is exposed cannot matter, and a populated registry says so.
fn exposing_svc() -> std::sync::Arc<super::Serving> {
    open_serving(
        services(&["svc=tcp:127.0.0.1:80"]),
        Semaphore::new(RAW_STREAM_OPEN_PERMITS),
    )
}

/// A dialer built from another rev is ANSWERED, and the answer names BOTH versions, so the person at
/// the keyboard learns what each end speaks instead of watching a stream close. Revert `Request::read`
/// to comparing four bytes for equality and the host writes nothing at all: the first assertion goes
/// red on a bare EOF, which is exactly the bug.
#[tokio::test]
async fn a_version_skewed_dialer_is_told_both_versions() {
    let (mut client, serve) = drive_frame(frame_with_magic(b"TB05").await, exposing_svc());
    let (served, response) = tokio::join!(serve, crate::protocol::Response::read(&mut client));

    let response = response.expect(
        "a version-skewed dialer must be answered on the wire; the response frame is frozen across \
         versions precisely so this one is readable",
    );
    assert_ne!(
        response,
        crate::protocol::Response::Ok,
        "a request frame this host cannot parse is never a success"
    );
    let detail = match &response {
        crate::protocol::Response::Refused(Refusal::BadRequest { detail }) => detail.as_str(),
        other => {
            panic!("a version skew is the peer's own grammar, so it is a bad request: {other:?}")
        }
    };
    assert!(
        detail.contains("TB05"),
        "the refusal names what the DIALER speaks: {detail}"
    );
    assert!(
        detail.contains("TB04"),
        "the refusal names what the HOST speaks: {detail}"
    );
    served.expect("the host answers the skew and ends the stream cleanly");
}

/// A genuinely foreign protocol keeps the old behaviour: no frame, no version, nothing. This is the
/// other half of the pair, and the pair is the whole change, which is about telling the two apart. The
/// frame differs from the one above in the PROTOCOL half of the magic and nowhere else.
#[tokio::test]
async fn a_foreign_protocol_is_told_nothing() {
    let (mut client, serve) = drive_frame(frame_with_magic(b"XX04").await, exposing_svc());
    let mut seen = Vec::new();
    let (served, read) = tokio::join!(serve, client.read_to_end(&mut seen));

    read.expect("the host closes the stream");
    assert!(
        seen.is_empty(),
        "a foreign protocol is answered with silence: we have nothing true to say to a protocol we do \
         not speak, and saying our version would hand a scanner a fingerprint. Got {seen:?}"
    );
    let host_error =
        served.expect_err("a foreign stream stays the host's own error, with no peer to answer");
    assert!(
        !host_error.to_string().contains("version"),
        "a foreign prefix is not a version skew, and the log must not say it is: {host_error}"
    );
}

/// The admission core with an unconstrained public pool and a fresh session: the predicate tests care
/// about the ruling, not the caps (the cap tests build their own [`Admission`]).
fn admit(
    gate: &Gate,
    public: &PublicServices,
    public_unsafe: &PublicServices,
    peer: SessionPeer,
    capability: Option<&str>,
    membership: Option<&str>,
    service: &Service,
) -> Result<super::AdmittedStream, super::HostRefusal> {
    super::admit(
        Admission {
            gate,
            public,
            public_unsafe,
            pool: &PublicPool::new(),
        },
        &PublicSession::default(),
        peer,
        capability,
        membership,
        service,
    )
}

/// An announced session that hands `serve_session` one pre-built stream: the session-level fixture
/// for the admission predicate, so the test drives the production path that reads the profile off
/// the session type, not the predicate in isolation.
struct AnnouncedSession {
    peer: NodeId,
    stream: tokio::sync::Mutex<
        Option<(
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
        )>,
    >,
}

impl Session for AnnouncedSession {
    type Security = Announced;
    type Write = tokio::io::WriteHalf<tokio::io::DuplexStream>;
    type Read = tokio::io::ReadHalf<tokio::io::DuplexStream>;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.stream
            .lock()
            .await
            .take()
            .ok_or(bifrost::Error::Closed)
    }

    async fn wait_closed(&self) {}

    /// A double that carries nothing has nothing to end.
    fn close(&self) {}
}

#[test]
fn a_single_service_node_needs_no_service_name() {
    let Services(one) = services(&["a=tcp:127.0.0.1:80"]);
    // A connector defaulting to `default` on a single-service node resolves to that one service.
    assert_eq!(resolve_single_service(svc("default"), &one).as_str(), "a");
    // A request that already names the exposed service is unchanged.
    assert_eq!(resolve_single_service(svc("a"), &one).as_str(), "a");

    let Services(two) = services(&["a=tcp:127.0.0.1:80", "b=tcp:127.0.0.1:81"]);
    // With two services, an unmatched request is left as-is (fails later with the hint, never guesses).
    assert_eq!(
        resolve_single_service(svc("default"), &two).as_str(),
        "default"
    );
}

/// The exposure ceiling refuses PRE-`Ok`: an open witness cannot mint a `Never` handler's proof, so the
/// wire sees the uniform `Refused(NotAdmitted)` and never a success. This is the wire-level ordering pin
/// for the `serve_request` split: a refactor that hoists `Response::Ok` above `handler.prepare` fails here.
#[tokio::test]
async fn an_open_witness_is_refused_before_ok_for_a_never_handler() {
    // Hand-build the serving context, bypassing the assembly interlock (which would refuse an open gate
    // over a Never handler outright): this isolates the bridge's prepare-time refusal on the serve path.
    let serving = Arc::new(super::Serving {
        gate: Gate::Open,
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services: Services(HashMap::new())
            .with_handler("locked", GatedNoop)
            .expect("`locked` binds"),
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool::new(),
        enabled: Box::new(AllEnabled),
        cuts: None,
    });
    let (mut client, serve) = drive_open("locked", serving);
    let (served, response) = tokio::join!(serve, crate::protocol::Response::read(&mut client));
    served.expect("serve_request returns Ok after writing a refusal");
    assert_eq!(
        response.expect("the refusal frame reads"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "the ceiling refusal is the uniform payload-free class, written with no success"
    );
}

/// The anti-starvation property: with the public-session pool FULL, a gated member dial
/// on its own session is still admitted and served, because only the public-admit seam touches the
/// pool. The public dial over the cap gets the same payload-free `NotAdmitted` a gate miss gives, and
/// dropping the public session releases its slot for the next public dial.
#[tokio::test]
async fn a_saturated_public_pool_never_starves_a_gated_member() {
    use crate::identity::AsVerifyKey as _;

    let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
    let gate = Gate::rooted(
        signet.verifying_key(),
        nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-public-starvation")),
    );
    // The badge is bound to the peer `drive_open_in` dials as, so the rooted gate admits it.
    let peer = bifrost::NodeId::from_ed25519_secret(&[9u8; 32]);
    let badge = signet
        .mint_member(
            peer.verify_key(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
        )
        .expect("mint member badge")
        .link()
        .expect("link");

    let services = Services(HashMap::new())
        .with_handler("open", OpenNoop)
        .expect("`open` binds")
        .with_handler("web", OpenNoop)
        .expect("`web` binds");
    let serving = Arc::new(super::Serving {
        gate,
        public: PublicServices(["open".to_owned()].into_iter().collect()),
        public_unsafe: PublicServices::default(),
        services,
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool {
            sessions: Arc::new(Semaphore::new(1)),
            streams: Arc::new(Semaphore::new(4)),
        },
        enabled: Box::new(AllEnabled),
        cuts: None,
    });

    // One public session reaches `open` and stays alive, holding the single public-session permit.
    let holder = Arc::new(PublicSession::default());
    let (mut holder_reader, holder_serve) =
        drive_open_in("open", Arc::clone(&serving), Arc::clone(&holder), None);
    let (served, response) = tokio::join!(
        holder_serve,
        crate::protocol::Response::read(&mut holder_reader)
    );
    served.expect("the serving future returns after the stream");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Ok,
        "the first public dial is admitted"
    );

    // The pool is full: a second public session is refused at the seam, with the uniform wire class.
    let stranger = Arc::new(PublicSession::default());
    let (mut stranger_reader, stranger_serve) =
        drive_open_in("open", Arc::clone(&serving), Arc::clone(&stranger), None);
    let (served, response) = tokio::join!(
        stranger_serve,
        crate::protocol::Response::read(&mut stranger_reader)
    );
    served.expect("the serving future returns after the refusal");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "a public dial over the session cap is refused with the uniform gate refusal"
    );

    // The anti-starvation property: a gated member dials its own session and is served while the
    // public pool is full. Its session presents a real badge, so it never touches the public pool.
    let member = Arc::new(PublicSession::default());
    let (mut member_reader, member_serve) = drive_open_in(
        "web",
        Arc::clone(&serving),
        Arc::clone(&member),
        Some(badge.to_string()),
    );
    let (served, response) = tokio::join!(
        member_serve,
        crate::protocol::Response::read(&mut member_reader)
    );
    served.expect("the serving future returns after the member stream");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Ok,
        "a gated member dial is served while the public pool is saturated"
    );

    // Close the public session: its permit returns to the pool, so the next public dial is admitted.
    drop(holder);
    let (mut fresh_reader, fresh_serve) = drive_open_in(
        "open",
        Arc::clone(&serving),
        Arc::new(PublicSession::default()),
        None,
    );
    let (served, response) = tokio::join!(
        fresh_serve,
        crate::protocol::Response::read(&mut fresh_reader)
    );
    served.expect("the serving future returns after the stream");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Ok,
        "a closed public session releases its permit for the next public dial"
    );
}

/// The public-stream cap: one parked public stream holds the single stream permit, so a
/// second public stream on the same (already classified) session is refused at the seam; releasing the
/// parked handler lets its stream end, drops the permit, and the next stream is admitted. Over-cap
/// refusal is the uniform wire class, written before any `Response::Ok`.
#[tokio::test]
async fn a_public_stream_over_the_cap_is_refused_and_released_when_it_ends() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let services = Services(HashMap::new())
        .with_handler(
            "park",
            Parked {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        )
        .expect("`park` binds");
    let serving = Arc::new(super::Serving {
        gate: Gate::Open,
        public: PublicServices(["park".to_owned()].into_iter().collect()),
        public_unsafe: PublicServices::default(),
        services,
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool {
            sessions: Arc::new(Semaphore::new(4)),
            streams: Arc::new(Semaphore::new(1)),
        },
        enabled: Box::new(AllEnabled),
        cuts: None,
    });

    // The first stream is admitted and parks in the handler, holding the one stream permit.
    let session = Arc::new(PublicSession::default());
    let (mut first_reader, first_serve) =
        drive_open_in("park", Arc::clone(&serving), Arc::clone(&session), None);
    let first = tokio::spawn(first_serve);
    assert_eq!(
        crate::protocol::Response::read(&mut first_reader)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "the first public stream is admitted"
    );
    entered.notified().await;

    // The cap is taken: a second public stream on the same session is refused, uniformly.
    let (mut second_reader, second_serve) =
        drive_open_in("park", Arc::clone(&serving), Arc::clone(&session), None);
    let (served, response) = tokio::join!(
        second_serve,
        crate::protocol::Response::read(&mut second_reader)
    );
    served.expect("the serving future returns after the refusal");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "a public stream over the cap is refused with the uniform gate refusal"
    );

    // Release the parked handler: the stream ends, its permit drops, and the next stream is admitted.
    release.add_permits(1);
    first
        .await
        .expect("the parked stream ends after its release")
        .expect("the serve future returns Ok");
    let (mut third_reader, third_serve) =
        drive_open_in("park", Arc::clone(&serving), Arc::clone(&session), None);
    let third = tokio::spawn(third_serve);
    assert_eq!(
        crate::protocol::Response::read(&mut third_reader)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "a stream permit released by a finished stream admits the next public stream"
    );
    entered.notified().await;
    release.add_permits(1);
    third
        .await
        .expect("the second parked stream ends")
        .expect("the serve future returns Ok");
}

/// The public-stream cap at its PRODUCTION value: `PUBLIC_STREAM_PERMITS = 4` is one node-wide,
/// service-blind pool. Four parked public streams on one service hold every slot (held to stream end,
/// idle or not), and a fifth public dial on a DIFFERENT public service is refused with the uniform
/// `NotAdmitted` rather than queued. Releasing the parked streams frees the slots for the next dial.
#[tokio::test]
async fn four_public_streams_hold_the_node_wide_pool_and_the_fifth_is_refused() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let services = Services(HashMap::new())
        .with_handler(
            "a",
            Parked {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        )
        .expect("`a` binds")
        .with_handler(
            "b",
            Parked {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        )
        .expect("`b` binds");
    let serving = Arc::new(super::Serving {
        gate: Gate::Open,
        public: PublicServices(["a".to_owned(), "b".to_owned()].into_iter().collect()),
        public_unsafe: PublicServices::default(),
        services,
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        // The PRODUCTION pool (not the small hand-built ones the other cap tests isolate with).
        public_pool: PublicPool::new(),
        enabled: Box::new(AllEnabled),
        cuts: None,
    });

    // Four public streams on `a`, each parked in the handler, holding one of the four slots for life.
    let session = Arc::new(PublicSession::default());
    let mut held = Vec::new();
    for _ in 0..PUBLIC_STREAM_PERMITS {
        let (mut reader, serve) =
            drive_open_in("a", Arc::clone(&serving), Arc::clone(&session), None);
        let serve = tokio::spawn(serve);
        assert_eq!(
            crate::protocol::Response::read(&mut reader)
                .await
                .expect("the response reads"),
            crate::protocol::Response::Ok,
            "a public stream under the cap is admitted"
        );
        entered.notified().await;
        held.push(serve);
    }

    // Service-blind: the pool is node-wide, so the fifth stream, aimed at the OTHER public service, is
    // refused with the uniform class (never queued behind the parked four).
    let (mut fifth_reader, fifth_serve) =
        drive_open_in("b", Arc::clone(&serving), Arc::clone(&session), None);
    let (served, response) = tokio::join!(
        fifth_serve,
        crate::protocol::Response::read(&mut fifth_reader)
    );
    served.expect("the serving future returns after the refusal");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "the fifth public stream is refused on the uniform class, on any public service"
    );

    // Releasing the four parked streams returns their slots; the next dial is admitted.
    release.add_permits(PUBLIC_STREAM_PERMITS);
    for serve in held {
        serve
            .await
            .expect("a parked stream ends after its release")
            .expect("the serve future returns Ok");
    }
    let (mut sixth_reader, sixth_serve) =
        drive_open_in("b", Arc::clone(&serving), Arc::clone(&session), None);
    let sixth = tokio::spawn(sixth_serve);
    assert_eq!(
        crate::protocol::Response::read(&mut sixth_reader)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "a released slot admits the next public stream"
    );
    entered.notified().await;
    release.add_permits(1);
    sixth
        .await
        .expect("the sixth stream ends")
        .expect("the serve future returns Ok");
}

/// A node serving one live `stdin:+lossy`-shaped broadcast, `cam`, to strangers through the unsafe
/// raw-stream overlay, beside a family-gated `vault`, on a rooted base and the PRODUCTION public pool.
/// Returns the serving context and the producer's end of the source, so a test decides when bytes flow.
///
/// `vault` is load-bearing for the refusal comparisons: a node serving exactly ONE name resolves any
/// unknown request to it, so without a second route an "absent service" dial would quietly become a
/// second dial of `cam` and a comparison against it would compare `cam` with itself.
fn public_lossy_broadcast() -> (Arc<super::Serving>, tokio::io::DuplexStream) {
    let (producer, source) = tokio::io::duplex(4096);
    let mut routes = HashMap::new();
    routes.insert(
        "cam".to_owned(),
        crate::tunnel::router::Route::family(crate::tunnel::router::Target::RawStream(
            crate::raw_stream::RawStream::lossy_from_reader(Box::new(source)),
        )),
    );
    let services = Services(routes)
        .with_handler("vault", GatedNoop)
        .expect("`vault` binds");
    let serving = Arc::new(super::Serving {
        gate: family_gate("public-lossy"),
        public: PublicServices::default(),
        public_unsafe: PublicServices(["cam".to_owned()].into_iter().collect()),
        services,
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool::new(),
        enabled: Box::new(AllEnabled),
        cuts: None,
    });
    (serving, producer)
}

/// Admit one stranger to `cam` on its own session and spawn its splice, returning the client's read half
/// once the host has answered `Ok` (failing with `why` if it did not). The splice task is returned so a
/// test can watch it end.
async fn admit_viewer(
    serving: &Arc<super::Serving>,
    why: &str,
) -> (
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<eyre::Result<()>>,
) {
    let (mut reader, serve) = drive_open_in(
        "cam",
        Arc::clone(serving),
        Arc::new(PublicSession::default()),
        None,
    );
    let splice = tokio::spawn(serve);
    assert_eq!(
        crate::protocol::Response::read(&mut reader)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "{why}"
    );
    (reader, splice)
}

/// Everything the host writes to a stranger dialing `service` on a fresh session: the whole wire answer,
/// read to the host's close, so two answers can be compared byte for byte rather than as decoded values.
/// Bounded, because a dial the host wrongly ADMITS never closes: without the bound a broken cap would
/// hang the suite instead of failing it.
async fn wire_answer(service: &str, serving: &Arc<super::Serving>) -> Vec<u8> {
    let (mut reader, serve) = drive_open_in(
        service,
        Arc::clone(serving),
        Arc::new(PublicSession::default()),
        None,
    );
    let mut answer = Vec::new();
    let answered = async {
        let (served, read) = tokio::join!(serve, reader.read_to_end(&mut answer));
        served.expect("the serving future returns after the refusal");
        read.expect("the host closes the stream after answering");
    };
    tokio::time::timeout(core::time::Duration::from_secs(5), answered)
        .await
        .expect("a refused dial is answered and closed; a stream still open was admitted");
    answer
}

/// A full public stream pool is not an oracle. With four strangers holding every public stream slot on a
/// live `+lossy` broadcast (the unsafe raw-stream overlay draws the same pool a safe public service does),
/// the fifth stranger's answer is BYTE-IDENTICAL to what a stranger gets for a service this node does not
/// serve at all, and for a gated service it holds no credential for. A dialer must not be able to tell
/// "this service exists and the node is full" from "there is nothing here for you", or the pool becomes a
/// way to confirm a service and to count its viewers.
#[tokio::test]
async fn a_full_public_pool_answers_exactly_like_an_absent_service() {
    let (serving, _producer) = public_lossy_broadcast();
    let mut viewers = Vec::new();
    for _ in 0..PUBLIC_STREAM_PERMITS {
        viewers.push(
            admit_viewer(
                &serving,
                "a stranger under the public stream cap is admitted",
            )
            .await,
        );
    }

    let full = wire_answer("cam", &serving).await;
    assert_eq!(
        full,
        wire_answer("nothing-here", &serving).await,
        "a full public pool must answer byte for byte like an absent service"
    );
    assert_eq!(
        full,
        wire_answer("vault", &serving).await,
        "a full public pool must answer byte for byte like a gate miss"
    );
    let mut decoded = full.as_slice();
    assert_eq!(
        crate::protocol::Response::read(&mut decoded)
            .await
            .expect("the answer is one response frame"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "the shared answer is the uniform not-admitted refusal"
    );
}

/// A viewer that goes away gives its public stream slot back. Four strangers hold the whole pool on a
/// live `+lossy` broadcast and the fifth is refused; one of the four then disconnects, and once its
/// splice notices (the next source byte fails to reach it), its slot returns and a new stranger is
/// admitted and receives the feed. Without the release, the fifth refusal would be permanent: the pool
/// would stay full of viewers that no longer exist, and nobody could watch until the node restarted.
///
/// Scope: this fixture's client has already half-closed its send side (it hangs up after the request),
/// and an in-process pipe reports a vanished peer as EOF, so this is the viewer the splice notices only
/// at its next write. A viewer that vanishes with its send half open errors the splice's read at once
/// over a real transport; no in-process test here can show that, so none claims to.
#[tokio::test]
async fn a_viewer_that_disconnects_gives_its_slot_to_the_next_stranger() {
    tokio::time::timeout(
        core::time::Duration::from_secs(30),
        a_viewer_that_disconnects_gives_its_slot_to_the_next_stranger_within_bound(),
    )
    .await
    .expect("every read completes; a hang here is a slot or a feed that never arrived");
}

async fn a_viewer_that_disconnects_gives_its_slot_to_the_next_stranger_within_bound() {
    use tokio::io::AsyncWriteExt as _;

    let (serving, mut producer) = public_lossy_broadcast();
    let mut viewers = Vec::new();
    for _ in 0..PUBLIC_STREAM_PERMITS {
        viewers.push(
            admit_viewer(
                &serving,
                "a stranger under the public stream cap is admitted",
            )
            .await,
        );
    }
    // Every viewer is live and receiving, not merely admitted.
    producer.write_all(b"a").await.expect("feed the broadcast");
    for (reader, _) in &mut viewers {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .await
            .expect("a viewer reads the feed");
        assert_eq!(&byte, b"a", "each admitted viewer receives the live feed");
    }
    assert_eq!(
        wire_answer("cam", &serving).await,
        wire_answer("vault", &serving).await,
        "the pool is full, so the fifth stranger is refused like any gate miss"
    );

    // One viewer disconnects. The source is live, so its next byte is where the splice finds the peer
    // gone: that write fails, the stream ends, and the slot it held drops with it.
    let (gone, splice) = viewers.swap_remove(0);
    drop(gone);
    producer.write_all(b"b").await.expect("feed the broadcast");
    // The splice's own result is the write it could not make; what matters is that it ENDED.
    let _broken_pipe = tokio::time::timeout(core::time::Duration::from_secs(5), splice)
        .await
        .expect("the departed viewer's splice ends at the next source byte")
        .expect("the splice task joins");

    let (mut next, _next_splice) = admit_viewer(
        &serving,
        "the slot a departed viewer held must return to the pool for the next stranger",
    )
    .await;
    producer.write_all(b"c").await.expect("feed the broadcast");
    let mut byte = [0u8; 1];
    next.read_exact(&mut byte)
        .await
        .expect("the new viewer reads the feed");
    assert_eq!(
        &byte, b"c",
        "the stranger admitted into the freed slot receives the live feed"
    );
}

/// AVAILABILITY: a flood of never-written `fifo:` opens is bounded
/// by `RAW_STREAM_OPEN_PERMITS` and, crucially, parks NO threads (the open is nonblocking; a writer-less
/// FIFO is awaited via the reactor, not a blocking-pool thread). With a cap of N, launch N+K concurrent
/// opens of a writer-less FIFO: exactly N acquire a permit and wait for a writer (no `Response` yet, no
/// parked thread), while every over-cap open is refused CLEANLY and FAST with the cap message. Proven with
/// a small explicit permit count so the test does not wait the full writer-wait timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_fifo_opens_cannot_exceed_the_cap() {
    use tokio::io::AsyncReadExt as _;

    // Hold the writer-wait lock so the no-leak test (which SHRINKS the writer-wait) cannot run concurrently
    // and make these parked opens time out early; here the wait must stay long so they genuinely park.
    let _lock = crate::raw_stream::WRITER_WAIT_TEST_LOCK.lock().await;

    let fifo = never_written_fifo("flood");
    let services = services(&[&format!("pipe=fifo:{}", fifo.display())]);

    const CAP: usize = 3;
    const OVER: usize = 4;
    // One shared serving context (so all opens draw on the SAME `CAP`-sized permit pool).
    let serving = open_serving(services, Semaphore::new(CAP));

    // CAP opens grab a permit and park in the blocking FIFO open; hold their serving futures so the
    // permits stay taken. They MUST NOT respond (they are blocked waiting for a writer that never comes).
    let mut parked = Vec::new();
    for _ in 0..CAP {
        let (mut client_read, serve) = drive_open("pipe", std::sync::Arc::clone(&serving));
        let handle = tokio::spawn(serve);
        // Give the open a moment to acquire its permit and enter the blocking syscall.
        let mut byte = [0u8; 1];
        let responded = tokio::time::timeout(
            core::time::Duration::from_millis(200),
            client_read.read(&mut byte),
        )
        .await;
        assert!(
            responded.is_err(),
            "a permit-holding FIFO open must PARK (no response), not answer before a writer appears"
        );
        parked.push((handle, client_read));
    }

    // With every permit taken, the OVER-cap opens must be refused immediately with the cap message, never
    // parking another thread. Each returns a `Response::Refused` a client can read at once.
    for _ in 0..OVER {
        let (mut client_read, serve) = drive_open("pipe", std::sync::Arc::clone(&serving));
        tokio::spawn(serve);
        let response = tokio::time::timeout(
            core::time::Duration::from_secs(2),
            crate::protocol::Response::read(&mut client_read),
        )
        .await
        .expect("an over-cap open must answer promptly, not park")
        .expect("read response");
        match response {
            crate::protocol::Response::Refused(bifrost::Refusal::Unavailable { detail }) => {
                assert!(
                    detail.as_str().contains("too many raw streams"),
                    "the over-cap refusal must name the cap: {detail}"
                );
            }
            other => panic!("an over-cap open must be refused with a detail, got: {other:?}"),
        }
    }

    // Release the parked opens so the test's runtime can shut down: open the FIFO's write end, which is the
    // writer they were awaiting. Their reactor readiness fires, the served splice runs, and the futures
    // finish. Nothing was leaked to clean up (the open is nonblocking and the wait is a reactor
    // registration, not a parked thread); this write end just unblocks the writer-wait so the tasks end
    // cleanly rather than being aborted mid-wait. Opening the FIFO `O_RDWR` never blocks.
    let writer_path = fifo.clone();
    tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _rdwr = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_RDWR)
            .open(&writer_path);
    })
    .await
    .expect("open the FIFO read-write end");
    for (handle, _client) in parked {
        handle.abort();
    }
    let _ = std::fs::remove_file(&fifo);
}

/// A single raw-stream open under the cap still works: one `file:` open (the common case) acquires a
/// permit, opens fast, and serves its bytes. The cap never penalizes normal single-stream serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_raw_stream_open_is_unaffected_by_the_cap() {
    use std::io::Write as _;

    use tokio::io::AsyncReadExt as _;

    let path = std::env::temp_dir().join(format!("tightbeam-cap-ok-{}", std::process::id()));
    let body = b"one open, under the cap";
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(body))
        .expect("write scratch file");

    let services = services(&[&format!("doc=file:{}", path.display())]);
    let serving = open_serving(services, Semaphore::new(RAW_STREAM_OPEN_PERMITS));

    let (mut client_read, serve) = drive_open("doc", serving);
    tokio::spawn(serve);
    // First the Ok, then the source's exact bytes.
    match crate::protocol::Response::read(&mut client_read)
        .await
        .expect("read response")
    {
        crate::protocol::Response::Ok => {}
        other => panic!("a single open under the cap must succeed, got: {other:?}"),
    }
    let mut got = Vec::new();
    client_read.read_to_end(&mut got).await.expect("read bytes");
    assert_eq!(got, body, "the single open serves the file's exact bytes");

    let _ = std::fs::remove_file(&path);
}

/// The live toggle, END TO END through the gate: a service named in the `<home>/disabled` file is
/// refused at `serve_request` with the SAME indistinguishable refusal a gate miss gives, and after the file
/// is rewritten to RE-ENABLE it, the very next stream against the SAME running serving context serves it,
/// with no restart (the mtime-watched [`FileDisabledList`] re-read the change). This is the property the
/// whole feature turns on: disable refuses live, enable restores live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_service_is_refused_then_restored_live_on_re_enable() {
    use std::io::Write as _;

    use tokio::io::AsyncReadExt as _;

    // A `file:` service so the served (enabled) path returns deterministic bytes with no external socket.
    let path = std::env::temp_dir().join(format!("tb-toggle-served-{}", std::process::id()));
    let body = b"served once re-enabled";
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(body))
        .expect("write scratch file");

    // The disabled-list file starts with `doc` disabled.
    let disabled = std::env::temp_dir().join(format!("tb-toggle-list-{}", std::process::id()));
    std::fs::write(&disabled, "doc\n").expect("write disabled list");

    let services = services(&[&format!("doc=file:{}", path.display())]);
    let enabled = crate::enabled::FileDisabledList::load(disabled.clone())
        .await
        .expect("load disabled list");
    // One serving context, held across the toggle: the same `Arc` serves both drives, so a pass proves the
    // LIVE re-read, not a rebuild.
    let serving = std::sync::Arc::new(super::Serving {
        gate: Gate::Open,
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services,
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool::new(),
        enabled: Box::new(enabled),
        cuts: None,
    });

    // Disabled: `serve_request` refuses with the uniform typed refusal, after admission and before any
    // dispatch.
    let (mut client_read, serve) = drive_open("doc", std::sync::Arc::clone(&serving));
    tokio::spawn(serve);
    match crate::protocol::Response::read(&mut client_read)
        .await
        .expect("read response")
    {
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted) => {}
        other => {
            panic!("a disabled service must be refused with the uniform class, got: {other:?}")
        }
    }

    // Re-enable: rewrite the file without `doc` and wait past the mtime-watch debounce (100ms).
    std::fs::write(&disabled, "\n").expect("re-enable doc");
    tokio::time::sleep(core::time::Duration::from_millis(250)).await;

    // The SAME serving context now serves it: Ok, then the file's exact bytes. No restart.
    let (mut client_read, serve) = drive_open("doc", std::sync::Arc::clone(&serving));
    tokio::spawn(serve);
    match crate::protocol::Response::read(&mut client_read)
        .await
        .expect("read response")
    {
        crate::protocol::Response::Ok => {}
        other => panic!("a re-enabled service must serve, got: {other:?}"),
    }
    let mut got = Vec::new();
    client_read.read_to_end(&mut got).await.expect("read bytes");
    assert_eq!(
        got, body,
        "the re-enabled service serves the file's exact bytes"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&disabled);
}

/// The disabled oracle is consulted AFTER admission, never before the gate. A gate miss must not touch it
/// at all: a pre-gate disabled check would let a cap-holder time "refused without a gate verify"
/// (disabled) against "refused after one" (enabled or absent) and learn the disabled set. The counting
/// oracle is the ordering pin: a gate miss leaves the count at 0, and an
/// admitted dial (open gate) reaches the check and is refused with the same uniform class.
#[tokio::test]
async fn a_disabled_service_is_refused_after_admission_not_before_the_gate() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// An enabled-oracle double that counts consultations and reports every service disabled.
    struct CountingDisabled(Arc<AtomicUsize>);
    impl crate::enabled::EnabledServices for CountingDisabled {
        fn is_enabled(&self, _service: &Service) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    let count = Arc::new(AtomicUsize::new(0));
    let signet = nauthy::Identity::from_secret(&[5u8; 32]).expect("valid secret");
    let rooted = Arc::new(super::Serving {
        gate: Gate::rooted(
            signet.verifying_key(),
            nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-disabled-order")),
        ),
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services: services(&["doc=tcp:127.0.0.1:80"]),
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool::new(),
        enabled: Box::new(CountingDisabled(Arc::clone(&count))),
        cuts: None,
    });

    // A dialer the rooted gate refuses (no badge): the uniform refusal, and the oracle is never consulted.
    let (mut refused_reader, refused_serve) = drive_open("doc", rooted);
    let (served, response) = tokio::join!(
        refused_serve,
        crate::protocol::Response::read(&mut refused_reader)
    );
    served.expect("the serving future returns after the refusal");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "a gate miss stays the uniform payload-free refusal"
    );
    assert_eq!(
        count.load(Ordering::Relaxed),
        0,
        "a gate miss must not consult the disabled oracle: the check is post-admission"
    );

    // An admitted dialer on an open gate reaches the check and is refused with the same uniform class.
    let open = Arc::new(super::Serving {
        gate: Gate::Open,
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services: services(&["doc=tcp:127.0.0.1:80"]),
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool::new(),
        enabled: Box::new(CountingDisabled(Arc::clone(&count))),
        cuts: None,
    });
    let (mut admitted_reader, admitted_serve) = drive_open("doc", open);
    let (served, response) = tokio::join!(
        admitted_serve,
        crate::protocol::Response::read(&mut admitted_reader)
    );
    served.expect("the serving future returns after the refusal");
    assert_eq!(
        response.expect("the response reads"),
        crate::protocol::Response::Refused(bifrost::Refusal::NotAdmitted),
        "an admitted dial to a disabled service gets the same uniform refusal"
    );
    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "an admitted dial reaches the disabled oracle once"
    );
}

/// The per-service admission core (BLOCKER-1): a HIT on EITHER open overlay (the safe `public` or the
/// unsafe raw-stream `public_unsafe`) admits any peer with no token (minting a `Slip`, never a member),
/// while EVERY miss -- a gated-present name AND a name the node does not serve at all -- takes the
/// identical family path and is refused. The one branch on the service name is the set-membership test;
/// there is no cheaper path for "absent" than for "gated-present", and a hit on either open set reveals
/// only the already-public fact that the service admits anyone.
#[test]
fn a_public_member_admits_a_stranger_and_every_miss_takes_the_family_path() {
    let gate = family_gate("admit");
    let public = super::PublicServices(["speed".to_owned()].into_iter().collect());
    // The unsafe overlay is disjoint from the safe one: `logs` is an unsafe-open raw stream, `speed` a
    // safe-open handler. Both admit a stranger; neither leaks into the other's set.
    let public_unsafe = super::PublicServices(["logs".to_owned()].into_iter().collect());
    let stranger = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);

    // HIT (safe overlay): the opened `speed` admits a tokenless stranger, and the witness is a Slip (an
    // opened service proves nothing about the peer), never a whole-node member.
    let admitted = admit(
        &gate,
        &public,
        &public_unsafe,
        SessionPeer {
            node: stranger,
            security: PROVEN,
        },
        None,
        None,
        &svc("speed"),
    )
    .expect("an opened service admits a stranger");
    assert!(
        !admitted.witness.is_member(),
        "an opened service admits as a Slip, never a whole-node member"
    );

    // HIT (unsafe overlay): a stranger reaching the unsafe-open raw stream is admitted the same way, also
    // as a Slip (§9 `an_unsafe_raw_stream_member_admits_a_stranger`).
    let unsafe_admitted = admit(
        &gate,
        &public,
        &public_unsafe,
        SessionPeer {
            node: stranger,
            security: PROVEN,
        },
        None,
        None,
        &svc("logs"),
    )
    .expect("an unsafe-open raw stream admits a stranger");
    assert!(
        !unsafe_admitted.witness.is_member(),
        "an unsafe-open raw stream admits as a Slip, never a whole-node member"
    );

    // MISS (gated-present): `control.stop` is served but NOT open on either overlay, so a stranger takes
    // the family path and is refused. MISS (absent): a name the node does not serve takes the SAME path.
    assert!(
        admit(
            &gate,
            &public,
            &public_unsafe,
            SessionPeer {
                node: stranger,
                security: PROVEN,
            },
            None,
            None,
            &svc("control.stop")
        )
        .is_err(),
        "a served-but-gated service is refused for a stranger (family path)"
    );
    assert!(
        admit(
            &gate,
            &public,
            &public_unsafe,
            SessionPeer {
                node: stranger,
                security: PROVEN,
            },
            None,
            None,
            &svc("nope")
        )
        .is_err(),
        "an absent service is refused for a stranger, on the same family path"
    );
}

/// Server-side slot-2 guard: the second slot is parsed ONLY when slot 1 is a signet-bound
/// slip. A plain member badge admits on slot 1 alone, so a hostile client's garbage in slot 2 is never
/// parsed and cannot turn a valid member dial into a refusal. The server guards this itself, never
/// trusting the dialer's attach logic.
#[test]
fn a_member_dial_ignores_a_second_slot_when_slot_one_is_not_signet_bound() {
    use crate::identity::AsVerifyKey as _;

    let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
    let gate = family_gate("guard");
    let public = super::PublicServices::default();
    let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
    let badge = signet
        .mint_member(
            peer.verify_key(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint member badge")
        .link()
        .expect("link");
    let admitted = admit(
        &gate,
        &public,
        &super::PublicServices::default(),
        SessionPeer {
            node: peer,
            security: PROVEN,
        },
        Some(badge.as_str()),
        Some("not a link"),
        &svc("web"),
    )
    .expect("a member badge admits on slot 1 alone; garbage in slot 2 is ignored");
    assert!(
        admitted.witness.is_member(),
        "a whole-node member badge admits as Member regardless of slot 2"
    );
}

/// The peer-proof predicate at the admission seam: an announced session cannot root-admit, even
/// with a genuine member badge bound to the announced key. The badge verifies (it is the signet's
/// own signature); that is exactly the replay an announced transport enables, so the predicate
/// refuses before the ruling and the node's own log names the declared profile.
#[test]
fn an_announced_session_cannot_root_admit_a_valid_badge() {
    use crate::identity::AsVerifyKey as _;

    let announced = Security {
        peer: PeerProof::Announced,
        channel: ChannelProtection::Plain,
    };
    let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
    let gate = family_gate("announced");
    let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
    let badge = signet
        .mint_member(
            peer.verify_key(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint member badge")
        .link()
        .expect("link");

    // The same badge over a proven session IS admitted (the control): the refusal below is the
    // profile, not the token.
    assert!(
        admit(
            &gate,
            &super::PublicServices::default(),
            &super::PublicServices::default(),
            SessionPeer {
                node: peer,
                security: PROVEN,
            },
            Some(badge.as_str()),
            None,
            &svc("web"),
        )
        .is_ok(),
        "a valid member badge is admitted over a proven session"
    );
    let refused = admit(
        &gate,
        &super::PublicServices::default(),
        &super::PublicServices::default(),
        SessionPeer {
            node: peer,
            security: announced,
        },
        Some(badge.as_str()),
        None,
        &svc("web"),
    )
    .expect_err("an announced session cannot root-admit, even with a valid badge");
    assert!(
        matches!(
            refused,
            super::HostRefusal::PeerNotProven {
                declared: PeerProof::Announced
            }
        ),
        "the local cause names the declared profile: {refused:?}"
    );
}

/// An anchored base wants a capability exactly as a rooted one does, so an announced session is refused
/// before the ruling, even with a slip the gate's own key issued and recorded.
#[test]
fn an_anchored_base_refuses_an_unproven_peer() {
    struct Unpinned;
    impl nauthy::PinSource for Unpinned {
        fn current(&self) -> Option<nauthy::VerifyKey> {
            None
        }
    }
    struct EveryId;
    impl nauthy::IssuedIds for EveryId {
        fn is_issued(&self, _id: &nauthy::RevocationId) -> bool {
            true
        }
    }

    let own = nauthy::Identity::from_secret(&[23u8; 32]).expect("valid secret");
    let gate = Gate::anchored(
        Unpinned,
        own.verifying_key(),
        nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-anchored-unproven")),
        EveryId,
    );
    let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
    let slip = own
        .mint(
            &svc("web"),
            nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint slip")
        .link()
        .expect("link");
    let admit_as = |security| {
        admit(
            &gate,
            &super::PublicServices::default(),
            &super::PublicServices::default(),
            SessionPeer {
                node: peer,
                security,
            },
            Some(slip.as_str()),
            None,
            &svc("web"),
        )
    };

    let admitted = admit_as(PROVEN).expect("the slip is admitted over a proven session");
    assert_eq!(
        admitted.ruled.first().map(nauthy::Cap::root),
        Some(own.verifying_key()),
        "and the slip is kept for the live cut"
    );
    let refused = admit_as(Security {
        peer: PeerProof::Announced,
        channel: ChannelProtection::Plain,
    })
    .expect_err("an announced session cannot be admitted by an anchored gate");
    assert!(
        matches!(
            refused,
            super::HostRefusal::PeerNotProven {
                declared: PeerProof::Announced
            }
        ),
        "the local cause names the declared profile: {refused:?}"
    );
}

/// The admission seam refuses an announced session even when the presented badge is genuine and
/// bound to the announced key: `serve_session` reads the session's declared profile, the predicate
/// refuses before any `ProvenPeer` is minted, and the wire gets the uniform `NotAdmitted` a gate
/// miss gives. The client writes the request with the RAW `Request::write` on purpose (a hostile or
/// legacy client bypasses the checked writer).
#[tokio::test]
async fn an_announced_session_is_refused_at_admission_with_the_uniform_answer() {
    use crate::identity::AsVerifyKey as _;
    use crate::protocol::{Request, Response};

    let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
    let peer = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]);
    let badge = signet
        .mint_member(
            peer.verify_key(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint member badge")
        .link()
        .expect("link");
    let serving = std::sync::Arc::new(super::Serving {
        gate: family_gate("announced-seam"),
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services: services(&["web=tcp:127.0.0.1:80"]),
        raw_stream_opens: Semaphore::new(RAW_STREAM_OPEN_PERMITS),
        public_pool: PublicPool::new(),
        enabled: Box::new(AllEnabled),
        cuts: None,
    });

    let (client, server) = tokio::io::duplex(1024);
    let (server_read, server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let session = AnnouncedSession {
        peer,
        stream: tokio::sync::Mutex::new(Some((server_write, server_read))),
    };

    let serve = serve_session(session, std::sync::Arc::clone(&serving));
    let (response, served) = tokio::join!(
        async {
            Request {
                service: "web".to_owned(),
                capability: Some(badge.to_string()),
                membership: None,
            }
            .write(&mut client_write)
            .await
            .expect("write request");
            Response::read(&mut client_read)
                .await
                .expect("read response")
        },
        serve
    );
    served.expect("the session drains after the refused stream");
    assert_eq!(
        response,
        Response::Refused(bifrost::Refusal::NotAdmitted),
        "an announced session gets the same payload-free refusal a gate miss gives"
    );
}

/// The flagship, at the tunnel level: a family-gated node opens ONE service per-service; a
/// stranger with no token is ADMITTED to that service but still REFUSED, uniformly, for a gated service
/// and for the always-on `control.stop`, which can never be opened. Proves the anti-oracle survives the
/// overlay: the gated refusals are the same payload-free class.
#[tokio::test]
async fn a_stranger_is_admitted_to_an_opened_service_and_uniformly_refused_for_the_rest() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // `open` is an OptIn responder (openable); `locked` is a Never handler (never openable);
            // `control.stop` stands in for the always-on gated control surface (also a Never handler).
            let services = Services(HashMap::new())
                .with_handler("open", OpenNoop)
                .expect("`open` binds")
                .with_handler("locked", GatedNoop)
                .expect("`locked` binds")
                .with_handler("control.stop", GatedNoop)
                .expect("`control.stop` binds");
            let exposer = prove(
                services,
                family_gate("flagship"),
                PublicRequest::new(["open".to_owned()]),
                PublicUnsafeRequest::none(),
            )
            .expect("`open` is OptIn, so it opens");

            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            tokio::task::spawn_local(async move {
                exposer
                    .run(&exposer_node, CancellationToken::new())
                    .await
                    .expect("runs");
            });

            // A stranger (no token) is ADMITTED to the opened service and reads it to a clean EOF.
            let session = consumer.connect(exposer_id).await.expect("connect");
            let opened = ServiceStream::open(&session, "open")
                .await
                .expect("a stranger is admitted to the opened service");
            opened
                .read_all()
                .await
                .expect("the opened service serves the stranger");

            // The same stranger is REFUSED for a gated service AND for control.stop, with the same
            // typed refusal: opening one service leaks nothing about the gated ones.
            let session = consumer.connect(exposer_id).await.expect("connect");
            let Err(gated) = ServiceStream::open(&session, "locked").await else {
                panic!("a gated service must refuse the stranger");
            };
            let session = consumer.connect(exposer_id).await.expect("connect");
            let Err(control) = ServiceStream::open(&session, "control.stop").await else {
                panic!("the always-on control surface must refuse the stranger");
            };
            assert_eq!(
                gated, control,
                "a gated service and the control surface refuse identically (no oracle)"
            );
            assert_eq!(
                gated,
                bifrost::Refusal::NotAdmitted,
                "the refusal is the payload-free uniform class"
            );
        })
        .await;
}

/// The member floor, end to end at the tunnel level: a route declared member-only serves a
/// whole-node member (the witness is borrowed for the check and then moved once into the handler, so the
/// single-use guarantee survives), and refuses a delegated slip for the SAME route and a tokenless
/// stranger with the SAME uniform class a gate miss gives. The echo route proves the floor covers a
/// non-handler dispatch arm too: the check precedes the whole dispatch match.
#[tokio::test]
async fn a_member_only_route_serves_a_member_and_uniformly_refuses_a_slip_and_a_stranger() {
    use crate::identity::AsVerifyKey as _;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let signet = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
            let gate = Gate::rooted(
                signet.verifying_key(),
                nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-member-floor")),
            );
            let services = services(&["reflect=echo:"])
                .with_handler("locked", GatedNoop)
                .expect("`locked` binds");
            let services = services
                .member_only("locked")
                .expect("`locked` is served")
                .member_only("reflect")
                .expect("`reflect` is served");
            let exposer = prove(
                services,
                gate,
                PublicRequest::none(),
                PublicUnsafeRequest::none(),
            )
            .expect("a member-only route under a rooted gate assembles");

            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            tokio::task::spawn_local(async move {
                exposer
                    .run(&exposer_node, CancellationToken::new())
                    .await
                    .expect("runs");
            });

            // A whole-node member: a badge the signet signed, bound to the member's proven mem id.
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet
                .mint_member(
                    member.node_id().verify_key(),
                    nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
                )
                .expect("mint a member badge")
                .link()
                .expect("link");
            let session = member.connect(exposer_id).await.expect("connect");
            for name in ["locked", "reflect"] {
                ServiceStream::open_with(&session, name, Some(badge.to_string()))
                    .await
                    .expect("a member badge passes the member floor");
            }

            // A delegated slip for `locked`: the gate's OWN ruling admits it (the slip grants the
            // service to this device), and the route floor turns that admission into the uniform refusal
            // a gate miss gives. A tokenless stranger gets the same refusal.
            let delegate = Node::new(MemTransport::bind(), NoDiscovery);
            let slip = signet
                .mint_bound(
                    &svc("locked"),
                    delegate.node_id().verify_key(),
                    nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
                )
                .expect("mint a bound slip")
                .link()
                .expect("link");
            let session = delegate.connect(exposer_id).await.expect("connect");
            let Err(slip_refused) =
                ServiceStream::open_with(&session, "locked", Some(slip.to_string())).await
            else {
                panic!("a slip must not pass a member-only route");
            };
            assert_eq!(
                slip_refused,
                bifrost::Refusal::NotAdmitted,
                "the floor refuses with the uniform payload-free class"
            );
            let session = delegate.connect(exposer_id).await.expect("connect");
            let Err(stranger_refused) = ServiceStream::open(&session, "locked").await else {
                panic!("a tokenless stranger must not pass the gate");
            };
            assert_eq!(
                stranger_refused, slip_refused,
                "a slip refusal is wire-identical to a gate miss (no member-only oracle)"
            );
        })
        .await;
}

/// B3: the uniform refusal renders descriptively (a reason a person can act on), never as the bare
/// wire word, so a `refused (…)` wrapper can never double it into `refused (refused)`.
#[test]
fn a_not_admitted_refusal_renders_descriptively_never_doubled() {
    let rendered = bifrost::Refusal::NotAdmitted.to_string();
    assert!(
        rendered.contains("not admitted"),
        "the uniform refusal renders as a reason a person can act on: {rendered:?}"
    );
    assert!(
        !rendered.contains("refused: refused"),
        "the refusal render must never double the bare word: {rendered:?}"
    );
}

/// A gate that ran out of time decided NOTHING about the dialer, so the wire must not send them the
/// answer that says it did. The uniform not-admitted refusal is a lie they act on: they stop retrying
/// and go looking for a credential nothing rejected, and a download of theirs turns into a permanent
/// 403 rather than a retry.
///
/// It goes on the refusal that is about the host, which is what that refusal now means: the reading
/// that let a dialer recover the admission bit from it was removed upstream as an oracle. Ruled
/// unanimously on 2026-09-20 that the outcome earns no wire code of its own, so this mapping is the
/// answer and not a stand-in for one. Every other gate cause stays uniform, which is settled and is
/// not what this reopens.
#[test]
fn an_undecided_gate_is_not_the_refusal_that_rules_on_the_dialer() {
    let undecided = super::wire_refusal(&super::HostRefusal::Gate(nauthy::Refusal::Undecided));

    // The negative runs FIRST: an inverted mapping must trip the assertion that names the lie, not a
    // shape check that fails and aborts before it is ever reached.
    assert!(
        !undecided.to_string().contains("not admitted"),
        "never the refusal that tells a dialer they lack authority: {undecided}"
    );
    assert!(
        matches!(undecided, Refusal::Unavailable { .. }),
        "an answer about this host goes on the refusal that is about this host: {undecided}"
    );

    for uniform in [
        nauthy::Refusal::Missing,
        nauthy::Refusal::NotGranted,
        nauthy::Refusal::Revoked,
    ] {
        let rendered = super::wire_refusal(&super::HostRefusal::Gate(uniform));
        assert!(
            matches!(rendered, Refusal::NotAdmitted),
            "a stranger's missing token, a revoked holder's, and a non-granting one stay \
             indistinguishable: {rendered}"
        );
    }
}

// What the first-traffic tests below cannot observe, said plainly rather than left to be assumed. They
// drive `tokio::io::duplex` halves under a paused clock, so they pin the ORDERING (dropped after the
// deadline and never before, disarmed by a byte moving either way) and not the wall-clock value: none of
// them shows that the window is long enough for any particular endpoint, because the greeter in them
// answers instantly. They do not observe what an overlay peer sees at the transport level, where a duplex
// half-close stands in for a real stream close, they do not capture the host's log event or its level, and
// they stand in for the shipped handlers with local doubles, so a handler whose first write happens inside
// a foreign library is covered by that consumer's own suite and not here.

/// The peer's greeting a server-speaks-first endpoint sends before its client says anything.
const GREETING: &[u8] = b"220 host ready\r\n";

/// The peer's opening bytes when the peer is the one who speaks first.
const HELLO: &[u8] = b"hello";

/// A server-speaks-first handler: it writes its greeting the instant it is handed the halves, then waits
/// on a peer that may never speak. An SSH identification string or an SMTP banner behind a forward is this
/// shape, and it is the case a read-only first-traffic deadline would kill. `finished` records that the
/// handler ran to its own end rather than being dropped under it.
struct Greeter {
    released: Arc<tokio::sync::Notify>,
    finished: Arc<AtomicBool>,
}

impl Handler for Greeter {
    type Exposure = OptIn;
    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        writer.write_all(GREETING).await?;
        writer.flush().await?;
        self.released.notified().await;
        self.finished.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// A peer-speaks-first handler: it waits for the peer's opening bytes, signals `heard`, and then holds the
/// stream open through a long silence (an interactive session that goes quiet after hello). `finished`
/// records that it ran to its own end rather than being dropped under it.
struct AfterPeer {
    heard: Arc<tokio::sync::Notify>,
    released: Arc<tokio::sync::Notify>,
    finished: Arc<AtomicBool>,
}

impl Handler for AfterPeer {
    type Exposure = OptIn;
    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        let mut opening = [0u8; HELLO.len()];
        reader.read_exact(&mut opening).await?;
        assert_eq!(
            opening, HELLO,
            "the watch wrapper forwards the bytes it counts"
        );
        self.heard.notify_one();
        self.released.notified().await;
        self.finished.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// Send `service`'s opening request and hand the caller the peer's WHOLE duplex end, un-split and open,
/// plus the host's serving future. [`drive_open`] closes the peer's write half as soon as the request is
/// sent, and a first-traffic test has to own whether the peer ever speaks again: an EOF is the one thing
/// a slow-loris never sends. The request is written before the host runs because the duplex buffer holds
/// it, so the peer can then be genuinely silent.
async fn dial_and_hold(
    service: &str,
    serving: std::sync::Arc<super::Serving>,
) -> (
    tokio::io::DuplexStream,
    impl core::future::Future<Output = eyre::Result<()>> + use<>,
) {
    let (mut peer_end, host_end) = tokio::io::duplex(1024);
    let (host_read, host_write) = tokio::io::split(host_end);
    crate::protocol::Request {
        service: service.to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut peer_end)
    .await
    .expect("write request");
    let peer = SessionPeer {
        node: bifrost::NodeId::from_ed25519_secret(&[9u8; 32]),
        security: PROVEN,
    };
    let serve = serve_request(
        peer,
        host_write,
        host_read,
        serving,
        std::sync::Arc::new(PublicSession::default()),
        None,
    );
    (peer_end, serve)
}

/// A peer that is ADMITTED and then says nothing is dropped. The pre-gate read bound stops at the gate,
/// and past it a silent stream pinned a task and its buffers for as long as the session lived.
///
/// The outer bound is the regression signal, not decoration. Delete the deadline at the dispatch site and
/// the parked handler never returns: the `timeout` below fires and this test goes red naming the defect,
/// instead of hanging the suite the way the defect hangs the node.
#[tokio::test(start_paused = true)]
async fn an_admitted_stream_that_never_speaks_is_dropped() {
    let entered = Arc::new(tokio::sync::Notify::new());
    // Never released: the handler holds both halves and touches neither, which is what the host sees when
    // an admitted peer opens a stream and goes quiet.
    let services = Services(HashMap::new())
        .with_handler(
            "park",
            Parked {
                entered: Arc::clone(&entered),
                release: Arc::new(Semaphore::new(0)),
            },
        )
        .expect("`park` binds");
    let (mut peer, serve) = dial_and_hold(
        "park",
        open_serving(services, Semaphore::new(RAW_STREAM_OPEN_PERMITS)),
    )
    .await;
    let host = tokio::spawn(serve);

    assert_eq!(
        crate::protocol::Response::read(&mut peer)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "the stream is admitted first: this bound is what happens AFTER a success, never instead of one"
    );
    entered.notified().await;
    let armed = tokio::time::Instant::now();

    let ended = tokio::time::timeout(FIRST_TRAFFIC_TIMEOUT * 6, host)
        .await
        .expect(
            "a stream that carries no bytes in either direction must be dropped: it was still open long \
             past the deadline, which is the whole defect this bound closes",
        );
    ended
        .expect("the serving task does not panic")
        .expect("dropping a silent stream is the host's own bound, not a host error");
    assert!(
        armed.elapsed() >= FIRST_TRAFFIC_TIMEOUT,
        "the deadline is armed at the handoff and not before: an admitted stream gets the whole window"
    );

    // What the peer observes, pinned: nothing after the `Ok`, then a close.
    let mut tail = Vec::new();
    peer.read_to_end(&mut tail)
        .await
        .expect("the host closed the stream");
    assert!(
        tail.is_empty(),
        "there is no refusal left to send once `Response::Ok` is on the wire, so the enforcement IS the \
         close; a late refusal would be a second answer to a request already answered. Got {tail:?}"
    );
}

/// The disarm is BIDIRECTIONAL, and this is the half that costs something when it is missed. A stream the
/// SERVER spoke on is not dropped, though the peer never says a word: a forward to an SSH or SMTP endpoint
/// is silent from the peer, by protocol, until the greeting arrives.
///
/// Wrap only the reader at the dispatch site, which is the simpler and wrong form of this bound, and this
/// test goes red at "a stream the host has already spoken on is never dropped": the handler is dropped
/// mid-greeting and every server-speaks-first forward breaks for behaving correctly.
#[tokio::test(start_paused = true)]
async fn a_stream_the_server_greets_survives_the_deadline() {
    let released = Arc::new(tokio::sync::Notify::new());
    let finished = Arc::new(AtomicBool::new(false));
    let services = Services(HashMap::new())
        .with_handler(
            "greet",
            Greeter {
                released: Arc::clone(&released),
                finished: Arc::clone(&finished),
            },
        )
        .expect("`greet` binds");
    let (mut peer, serve) = dial_and_hold(
        "greet",
        open_serving(services, Semaphore::new(RAW_STREAM_OPEN_PERMITS)),
    )
    .await;
    let host = tokio::spawn(serve);

    assert_eq!(
        crate::protocol::Response::read(&mut peer)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "the stream is admitted"
    );
    let mut greeting = vec![0u8; GREETING.len()];
    peer.read_exact(&mut greeting)
        .await
        .expect("the greeting reads");

    // The peer now says nothing at all, well past the deadline.
    tokio::time::sleep(FIRST_TRAFFIC_TIMEOUT * 3).await;
    assert!(
        !host.is_finished(),
        "a stream the host has already spoken on is never dropped: the deadline disarms on the first byte \
         in EITHER direction, and a read-only disarm would kill every server-speaks-first forward"
    );
    assert!(
        !finished.load(Ordering::Relaxed),
        "the handler is still serving its stream, not finished with it"
    );
    assert_eq!(
        greeting, GREETING,
        "the watch wrapper forwards the bytes it counts, unchanged"
    );

    released.notify_one();
    tokio::time::timeout(FIRST_TRAFFIC_TIMEOUT, host)
        .await
        .expect("the released handler returns")
        .expect("the serving task does not panic")
        .expect("a disarmed stream ends on the handler's own terms");
    assert!(
        finished.load(Ordering::Relaxed),
        "the handler ran to its own end rather than being dropped under it"
    );
}

/// A peer that speaks promptly is untouched, and stays untouched however long it goes quiet afterwards:
/// the bound is on a stream that never spoke, never on an idle one, so it can never truncate an exchange
/// already under way.
///
/// Stop counting READ bytes as traffic, the other half of the bidirectional disarm, and this goes red at
/// the same assertion.
#[tokio::test(start_paused = true)]
async fn a_peer_that_speaks_promptly_is_unaffected() {
    let heard = Arc::new(tokio::sync::Notify::new());
    let released = Arc::new(tokio::sync::Notify::new());
    let finished = Arc::new(AtomicBool::new(false));
    let services = Services(HashMap::new())
        .with_handler(
            "after",
            AfterPeer {
                heard: Arc::clone(&heard),
                released: Arc::clone(&released),
                finished: Arc::clone(&finished),
            },
        )
        .expect("`after` binds");
    let (mut peer, serve) = dial_and_hold(
        "after",
        open_serving(services, Semaphore::new(RAW_STREAM_OPEN_PERMITS)),
    )
    .await;
    let host = tokio::spawn(serve);

    assert_eq!(
        crate::protocol::Response::read(&mut peer)
            .await
            .expect("the response reads"),
        crate::protocol::Response::Ok,
        "the stream is admitted"
    );
    peer.write_all(HELLO).await.expect("the peer speaks");
    peer.flush()
        .await
        .expect("the peer's bytes are on the wire");
    heard.notified().await;

    // The exchange now goes quiet for far longer than the first-traffic window.
    tokio::time::sleep(FIRST_TRAFFIC_TIMEOUT * 3).await;
    assert!(
        !host.is_finished(),
        "a stream that carried the peer's bytes is never dropped for going quiet afterwards: this is a \
         first-traffic bound, not an idle bound, and an idle bound is not the dispatcher's to set"
    );

    released.notify_one();
    tokio::time::timeout(FIRST_TRAFFIC_TIMEOUT, host)
        .await
        .expect("the released handler returns")
        .expect("the serving task does not panic")
        .expect("a disarmed stream ends on the handler's own terms");
    assert!(
        finished.load(Ordering::Relaxed),
        "the handler ran to its own end rather than being dropped under it"
    );
}

/// A peer writer that never accepts a byte: a QUIC receiver advertising a zero stream window.
struct NoCredit;

impl tokio::io::AsyncWrite for NoCredit {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
        _buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        core::task::Poll::Pending
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Pending
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Pending
    }
}

/// A `stdin:` holder that grants no credit at all never takes even its `Ok` byte. It is judged like any
/// other stalled holder, from that first refused byte, so a contender dialing a window later takes the
/// seat. An `Ok` written before the seat's metered, preemptible scope would park unjudged and hold the
/// seat for as long as the connection lived.
#[tokio::test(start_paused = true)]
async fn a_stdin_holder_that_never_takes_its_ok_is_displaced_by_a_contender() {
    let mut map = HashMap::new();
    map.insert(
        "cam".to_owned(),
        crate::tunnel::router::Route::family(crate::tunnel::router::Target::RawStream(
            crate::raw_stream::RawStream::from_reader(Box::new(tokio::io::repeat(b'x'))),
        )),
    );
    let serving = open_serving(Services(map), Semaphore::new(RAW_STREAM_OPEN_PERMITS));

    let mut request = Vec::new();
    crate::protocol::Request {
        service: "cam".to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut request)
    .await
    .expect("write request");
    let holder = SessionPeer {
        node: bifrost::NodeId::from_ed25519_secret(&[8u8; 32]),
        security: PROVEN,
    };
    // The holder's upstream half: its request, then silence, held open for the whole test.
    let (mut holder_upstream, server_read) = tokio::io::duplex(1024);
    holder_upstream
        .write_all(&request)
        .await
        .expect("send the request");
    let holding = tokio::spawn(serve_request(
        holder,
        NoCredit,
        server_read,
        Arc::clone(&serving),
        Arc::new(PublicSession::default()),
        None,
    ));

    tokio::time::sleep(crate::raw_stream::STALL_WINDOW + core::time::Duration::from_secs(1)).await;
    let (mut contender, serve) = drive_open("cam", serving);
    let contending = tokio::spawn(serve);
    let response = crate::protocol::Response::read(&mut contender)
        .await
        .expect("read the response");
    assert!(
        matches!(response, crate::protocol::Response::Ok),
        "a holder that never took its `Ok` is displaced: {response:?}"
    );
    contending.abort();
    holding.abort();
    drop(holder_upstream);
}
