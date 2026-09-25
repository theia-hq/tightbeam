//! Transport-security enforcement, end to end over a profile-shaped in-process transport.
//!
//! [`Profiled`] moves the same mem bytes under a chosen declaration (`Announced`, `Sealed`), so a test
//! picks the profile without a network and the behavior under test is the profile rule, not a wire. The
//! sibling unit tests cover the checked writer byte-for-byte (`protocol_tests.rs`) and the admission
//! predicate's typed cause (`tunnel.rs`); these prove the seams through the public API: a credential
//! dial over an announced transport refuses before any write, a sealed transport carries the same dial
//! unchanged, a rooted gate refuses to arm over announced, and the compile-time credential API dials a
//! proven profile.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::marker::PhantomData;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use bifrost::{
    Addr, Announced, ConnInfo, Error, NoDiscovery, Node, NodeId, PeerProof, Sealed,
    SecurityProfile, Session, Transport,
};
use bifrost_mem::MemTransport;
use nauthy::{FileDenylist, Identity};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::protocol::RequestWriteError;
use tightbeam::security::TransportInsecure;
use tightbeam::tunnel::{self, CancellationToken, Connector, PresentingConnector, Router};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The root every gate here trusts and every badge is minted from.
const ROOT_SECRET: [u8; 32] = [42u8; 32];

/// A transport whose declared profile is `P`, moving the same in-process bytes as [`MemTransport`].
///
/// The profile-rule fixture: the bytes are mem's (no network, no timing), while the declaration is the
/// test's, so a `Sealed` wrapper passes where an `Announced` wrapper refuses.
struct Profiled<T, P> {
    inner: T,
    profile: PhantomData<P>,
}

/// A session over the same in-process bytes, carrying the wrapper's declared profile.
struct ProfiledSession<S, P> {
    inner: S,
    profile: PhantomData<P>,
}

/// Wrap a mem endpoint under the declared profile `P`.
fn profiled<P: SecurityProfile>(inner: MemTransport) -> Profiled<MemTransport, P> {
    Profiled {
        inner,
        profile: PhantomData,
    }
}

impl<T: Transport, P: SecurityProfile> Transport for Profiled<T, P> {
    type Security = P;
    type Session = ProfiledSession<T::Session, P>;

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error> {
        Ok(ProfiledSession {
            inner: self.inner.connect(addr).await?,
            profile: PhantomData,
        })
    }

    async fn accept(&self) -> Result<Self::Session, Error> {
        Ok(ProfiledSession {
            inner: self.inner.accept().await?,
            profile: PhantomData,
        })
    }

    async fn close(&self) {
        self.inner.close().await
    }
}

impl<S: Session, P: SecurityProfile> Session for ProfiledSession<S, P> {
    type Security = P;
    type Write = S::Write;
    type Read = S::Read;

    fn peer(&self) -> NodeId {
        self.inner.peer()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        self.inner.open_bi().await
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        self.inner.accept_bi().await
    }

    async fn wait_closed(&self) {
        self.inner.wait_closed().await
    }

    fn close(&self) {
        self.inner.close();
    }

    fn conn_info(&self) -> ConnInfo {
        self.inner.conn_info()
    }
}

/// A credential dial over an announced transport refuses with the typed local error, before the local
/// port binds and before any byte could be written. The peer is a bound but never-accepted endpoint, so
/// connect and stream-open succeed over mem: the refusal can only come from the checked credential
/// writer reading the session's declared profile.
#[tokio::test]
async fn a_gated_dial_over_an_announced_transport_refuses_before_any_write() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let peer = profiled::<Announced>(MemTransport::bind());
            let peer_id = peer.node_id();
            let consumer = Node::new(profiled::<Announced>(MemTransport::bind()), NoDiscovery);

            let root = Identity::from_secret(&ROOT_SECRET).unwrap();
            let badge = root
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    nauthy::Request::expires_in(Duration::from_secs(3600)),
                )
                .unwrap()
                .link()
                .unwrap();

            let port = free_port().await;
            // Bound the dial: under a predicate regression the credential write would succeed and
            // `preflight` would await a `Response` from the never-accepted peer forever. The timeout turns
            // that hang into a fast failure at the assertion below.
            let error = tokio::time::timeout(
                Duration::from_secs(5),
                Connector::to_node(peer_id, "web".parse().unwrap(), Some(badge))
                    .preflight(&consumer, port),
            )
            .await
            .expect("the refusal must return, not hang")
            .err()
            .expect("an announced transport must refuse a credential dial");
            assert!(
                matches!(
                    error.downcast_ref::<RequestWriteError>(),
                    Some(RequestWriteError::Insecure(TransportInsecure {
                        declared: PeerProof::Announced
                    }))
                ),
                "the refusal is the typed insecure-transport error: {error:#}"
            );
            TcpListener::bind(("127.0.0.1", port))
                .await
                .expect("a refused dial must not bind the local port");
            drop(peer);
        })
        .await;
}

/// A sealed transport carries a gated, credential-presenting dial unchanged: the same member badge the
/// announced test refuses is admitted, forwarded, and echoes bytes.
#[tokio::test]
async fn a_sealed_transport_carries_a_gated_dial_unchanged() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let echo = spawn_echo().await;
            let exposer = Node::new(profiled::<Sealed>(MemTransport::bind()), NoDiscovery);
            let exposer_id = exposer.node_id();
            tokio::task::spawn_local(async move {
                let gate = tunnel::resolve_gate(Some(root_id()), empty_denylist().await).unwrap();
                Router::new(gate)
                    .forward("web".parse().unwrap(), &format!("tcp:{echo}"))
                    .unwrap()
                    .expose()
                    .unwrap()
                    .run(&exposer, CancellationToken::new())
                    .await
                    .unwrap();
            });

            let consumer = Node::new(profiled::<Sealed>(MemTransport::bind()), NoDiscovery);
            let badge = member_badge(&consumer);
            let port = free_port().await;
            let forward = Connector::to_node(exposer_id, "web".parse().unwrap(), Some(badge))
                .preflight(&consumer, port)
                .await
                .expect("a sealed transport carries the credential dial");
            tokio::task::spawn_local(async move {
                let _ = forward.run().await;
            });

            assert_eq!(
                echo_once(port, b"sealed").await.as_deref(),
                Some(&b"sealed"[..]),
                "the admitted forward carries the bytes"
            );
        })
        .await;
}

/// The compile-time credential API dials a gated service unchanged over a proven profile: mem is
/// in-process, which satisfies `PeerProven`, so the typed path compiles and admits exactly as the
/// runtime path does.
#[tokio::test]
async fn a_presenting_connector_dials_a_gated_service_over_a_proven_profile() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let echo = spawn_echo().await;
            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();
            tokio::task::spawn_local(async move {
                let gate = tunnel::resolve_gate(Some(root_id()), empty_denylist().await).unwrap();
                Router::new(gate)
                    .forward("web".parse().unwrap(), &format!("tcp:{echo}"))
                    .unwrap()
                    .expose()
                    .unwrap()
                    .run(&exposer, CancellationToken::new())
                    .await
                    .unwrap();
            });

            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = member_badge(&consumer);
            let port = free_port().await;
            let forward = PresentingConnector::to_node(exposer_id, "web".parse().unwrap(), badge)
                .preflight(&consumer, port)
                .await
                .expect("the compile-time credential API dials a proven profile");
            tokio::task::spawn_local(async move {
                let _ = forward.run().await;
            });

            assert_eq!(
                echo_once(port, b"typed").await.as_deref(),
                Some(&b"typed"[..]),
                "the typed dial carries the bytes"
            );
        })
        .await;
}

/// A rooted gate over an announced transport refuses to arm, with a teaching error naming the declared
/// profile: a node that could never root-admit does not start. A genuinely open gate still arms, since
/// it proves nothing about anyone and reads no peer proof.
#[tokio::test]
async fn a_rooted_gate_over_an_announced_transport_refuses_to_arm() {
    let node = Node::new(profiled::<Announced>(MemTransport::bind()), NoDiscovery);

    let rooted =
        Router::new(tunnel::resolve_gate(Some(root_id()), empty_denylist().await).unwrap())
            .forward("web".parse().unwrap(), "tcp:127.0.0.1:80")
            .unwrap()
            .expose()
            .unwrap();
    let error = rooted
        .prove_security::<Profiled<MemTransport, Announced>>()
        .expect_err("a rooted gate must not arm over an announced transport");
    let message = format!("{error:#}");
    assert!(
        message.contains("declares announced peer proof"),
        "the refusal teaches the declared profile: {message}"
    );
    assert!(
        rooted.run(&node, CancellationToken::new()).await.is_err(),
        "run repeats the construction check"
    );

    let open = Router::new(nauthy::Gate::Open)
        .forward("web".parse().unwrap(), "tcp:127.0.0.1:80")
        .unwrap()
        .expose()
        .unwrap();
    open.prove_security::<Profiled<MemTransport, Announced>>()
        .expect("an open gate needs no peer proof");
    tokio::select! {
        result = open.run(&node, CancellationToken::new()) => {
            panic!("an open exposer runs until cancelled: {result:?}");
        }
        () = tokio::task::yield_now() => {}
    }
}

/// The root's node id: the root every test gate trusts.
fn root_id() -> NodeId {
    NodeId::from_ed25519_secret(&ROOT_SECRET)
}

/// A member badge bound to `device`, rooted at the test root: valid on its own, and meaningless over
/// an announced transport because the binding rests on a key the transport did not prove.
fn member_badge<T: Transport, D: bifrost::Discovery>(device: &Node<T, D>) -> nauthy::Link {
    Identity::from_secret(&ROOT_SECRET)
        .unwrap()
        .mint_member(
            device.node_id().verify_key().expect("a checked key"),
            nauthy::Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap()
        .link()
        .unwrap()
}

/// Spawn a local TCP echo service and return its address.
async fn spawn_echo() -> core::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
            tokio::task::spawn_local(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Send `probe` through a bound forward and return the echo if it arrives within a short window (a
/// refused or never-bound port returns `None`).
async fn echo_once(port: u16, probe: &[u8]) -> Option<Vec<u8>> {
    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            client = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = client?;
    client.write_all(probe).await.ok()?;
    let mut echoed = vec![0u8; probe.len()];
    match tokio::time::timeout(Duration::from_millis(500), client.read_exact(&mut echoed)).await {
        Ok(Ok(_)) => Some(echoed),
        _ => None,
    }
}

/// A free local TCP port.
async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

/// An empty revocation denylist: these tests exercise the profile rule, not revocation. The path is unique
/// per call, so the tests that run concurrently cannot share (and race on) one file.
async fn empty_denylist() -> FileDenylist {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "tightbeam-security-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    FileDenylist::load(path).await.unwrap()
}
