//! Proven-only routes: a peer whose key the transport proved, and which the route knows, reaches the route
//! with no token; nothing else does, and nothing on it reaches another route. The node's proven pool holds
//! only known keys, frees every slot by the deadline, and a key revoked mid-stream is cut.

use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use bifrost::{
    Announced, ChannelProtection, NoDiscovery, Node, NodeId, PeerProof, Refusal, Security, Session,
};
use bifrost_mem::MemTransport;
use nauthy::{Cap, Gate, Identity, Origin, Revocations, VerifyKey};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore};

use super::{Admission, HostRefusal, Proven, admit};
use crate::enabled::{AllEnabled, EnabledServices};
use crate::identity::AsVerifyKey as _;
use crate::open_policy::ProvenOnly;
use crate::tunnel::cut::{AdmittedChains, LiveCuts};
use crate::tunnel::exposer::{
    PROVEN_STREAM_DEADLINE, PROVEN_STREAM_PERMITS, PublicPool, PublicSession, Serving, SessionPeer,
    serve_session,
};
use crate::tunnel::fixtures::{GatedNoop, ServiceStream, svc};
use crate::tunnel::router::{Access, PublicServices, Route, Services, Target};
use crate::tunnel::{
    BoxRead, BoxWrite, CancellationToken, Exposer, Handler, Router, ServeError, Served,
};

/// The proven-only route every test serves.
const PICKUP: &str = "pickup";

/// The key a rooted gate roots at in these tests.
fn signet() -> Identity {
    Identity::from_secret(&[41u8; 32]).expect("valid secret")
}

/// Revoked device keys, in memory, read by the gate at admission and by the cut on every sweep: one
/// instance for both, as a product caller wires it.
#[derive(Default)]
struct Keys(Mutex<HashSet<VerifyKey>>);

impl Keys {
    fn revoke(&self, key: VerifyKey) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
    }

    fn holds(&self, key: &VerifyKey) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key)
    }
}

impl Revocations for Keys {
    fn is_revoked(&self, _cap: &Cap) -> bool {
        false
    }

    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.holds(peer)
    }
}

impl LiveCuts for Keys {
    fn cuts(&self, _chains: &AdmittedChains) -> bool {
        false
    }

    fn revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.holds(peer)
    }
}

/// A proven-only handler that answers one byte, then holds the stream without reading or closing it: the
/// peer that keeps a slot for as long as the host lets it. The byte moves the stream past the first-traffic
/// deadline, so only the proven deadline or a cut can end it.
struct Hold {
    entered: Arc<Notify>,
}

impl Handler for Hold {
    type Exposure = ProvenOnly;

    async fn serve(
        &self,
        served: Served<Self>,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        assert_eq!(served.origin(), Origin::Proven);
        writer.write_all(b"!").await?;
        writer.flush().await?;
        self.entered.notify_one();
        core::future::pending::<()>().await;
        Ok(())
    }
}

/// A router over a rooted gate on `keys`: the proven-only [`PICKUP`] route knowing exactly `known`, the
/// family `ping` echo, and the member-only `locked` route.
fn router(keys: &Arc<Keys>, known: HashSet<VerifyKey>, entered: &Arc<Notify>) -> Router {
    Router::new(Gate::rooted(signet().verifying_key(), Arc::clone(keys)))
        .proven_service(
            svc(PICKUP),
            Hold {
                entered: Arc::clone(entered),
            },
            move |key| known.contains(key),
        )
        .expect("`pickup` binds")
        .echo(svc("ping"))
        .expect("`ping` binds")
        .member_service(svc("locked"), GatedNoop)
        .expect("`locked` binds")
}

/// Bind the exposer on its own in-process node and serve it for the rest of the test.
fn serve(exposer: Exposer) -> NodeId {
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let id = node.node_id();
    tokio::task::spawn_local(async move {
        exposer
            .run(&node, CancellationToken::new())
            .await
            .expect("exposer runs");
    });
    id
}

/// Open `n` streams to [`PICKUP`] on `session`, each admitted and answered, and keep them open.
async fn hold<S: Session>(
    session: &S,
    entered: &Notify,
    n: usize,
) -> Vec<ServiceStream<S::Write, S::Read>> {
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let mut stream = ServiceStream::open(session, PICKUP)
            .await
            .expect("a known key is admitted while the pool has room");
        let mut byte = [0u8; 1];
        stream
            .reader
            .read_exact(&mut byte)
            .await
            .expect("the route answers");
        entered.notified().await;
        held.push(stream);
    }
    held
}

/// The admission core over one proven-only route, for the ruling tests that need no transport.
fn serving_state(
    keys: &Arc<Keys>,
    knows: impl Fn(&VerifyKey) -> bool + Send + Sync + 'static,
) -> Serving {
    let mut routes = HashMap::new();
    routes.insert(
        PICKUP.to_owned(),
        Route {
            target: Target::Handler(Arc::new(Hold {
                entered: Arc::new(Notify::new()),
            })),
            access: Access::ProvenOnly(Arc::new(knows)),
        },
    );
    Serving {
        gate: Gate::rooted(signet().verifying_key(), Arc::clone(keys)),
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        services: Services(routes),
        raw_stream_opens: Semaphore::new(1),
        public_pool: PublicPool::new(),
        proven_pool: Arc::new(Semaphore::new(PROVEN_STREAM_PERMITS)),
        enabled: Box::new(AllEnabled),
        cuts: None,
    }
}

/// An announced session that hands `serve_session` one pre-built stream: the peer merely claims its key.
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

    fn close(&self) {}
}

/// A peer that only announced its key never reaches a proven-only route, even one that knows the key it
/// announced: the witness would say the transport proved a key it did not. The check runs whatever the
/// base gate is, not only when the gate wants a token.
#[tokio::test]
async fn proven_only_route_refuses_an_announced_peer() {
    use crate::protocol::{Request, Response};

    let peer = NodeId::from_ed25519_secret(&[43u8; 32]);
    let keys = Arc::new(Keys::default());
    let serving = Arc::new(serving_state(&keys, |_| true));

    let (client, server) = tokio::io::duplex(1024);
    let (server_read, server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let session = AnnouncedSession {
        peer,
        stream: tokio::sync::Mutex::new(Some((server_write, server_read))),
    };
    let (response, served) = tokio::join!(
        async {
            Request {
                service: PICKUP.to_owned(),
                capability: None,
                membership: None,
            }
            .write(&mut client_write)
            .await
            .expect("write request");
            Response::read(&mut client_read)
                .await
                .expect("read response")
        },
        serve_session(session, Arc::clone(&serving))
    );
    served.expect("the session drains after the refused stream");
    assert_eq!(
        response,
        Response::Refused(Refusal::NotAdmitted),
        "an announced key never reaches a proven-only route"
    );

    // The same ruling, read at the core: the transport's claim is what refused it.
    let announced = SessionPeer {
        node: peer,
        security: Security {
            peer: PeerProof::Announced,
            channel: ChannelProtection::Aead,
        },
    };
    let ruled = admit(
        Admission {
            gate: &serving.gate,
            public: &serving.public,
            public_unsafe: &serving.public_unsafe,
            pool: &serving.public_pool,
            proven: Proven {
                routes: &serving.services,
                pool: &serving.proven_pool,
            },
        },
        &PublicSession::default(),
        announced,
        None,
        None,
        &svc(PICKUP),
    );
    assert!(
        matches!(ruled, Err(HostRefusal::PeerNotProven { .. })),
        "refused because the transport did not prove the key: {ruled:?}"
    );
}

/// A proven witness is minted for a proven-only route and nowhere else: a peer with no token that such a
/// route knows reaches it, and the same peer is refused on a family route and on a member route with the
/// uniform answer a stranger gets.
#[tokio::test]
async fn a_proven_witness_reaches_no_family_or_member_route() {
    let keys = Arc::new(Keys::default());
    let serving = serving_state(&keys, |_| true);
    let peer = SessionPeer {
        node: NodeId::from_ed25519_secret(&[44u8; 32]),
        security: Security {
            peer: PeerProof::Proven,
            channel: ChannelProtection::Aead,
        },
    };
    let admission = Admission {
        gate: &serving.gate,
        public: &serving.public,
        public_unsafe: &serving.public_unsafe,
        pool: &serving.public_pool,
        proven: Proven {
            routes: &serving.services,
            pool: &serving.proven_pool,
        },
    };
    let pickup = admit(
        admission,
        &PublicSession::default(),
        peer,
        None,
        None,
        &svc(PICKUP),
    )
    .expect("a known proven key reaches the proven-only route");
    assert_eq!(pickup.witness.origin(), Origin::Proven);
    for name in ["ping", "locked"] {
        let ruled = admit(
            admission,
            &PublicSession::default(),
            peer,
            None,
            None,
            &svc(name),
        );
        assert!(
            matches!(ruled, Err(HostRefusal::Gate(nauthy::Refusal::Missing))),
            "`{name}` takes the family path, where a peer with no token is missing one: {ruled:?}"
        );
    }

    // End to end: the same peer, tokenless, is answered on the proven-only route and refused elsewhere.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let entered = Arc::new(Notify::new());
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let known = HashSet::from([consumer.node_id().verify_key().expect("a checked key")]);
            let host = serve(router(&keys, known, &entered).expose().expect("assembles"));
            let session = consumer.connect(host).await.expect("connect");
            let _held = hold(&session, &entered, 1).await;
            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let stranger = stranger.connect(host).await.expect("connect");
            let Err(miss) = ServiceStream::open(&stranger, "ping").await else {
                panic!("a stranger with no token is refused on a family route");
            };
            for name in ["ping", "locked"] {
                let Err(refused) = ServiceStream::open(&session, name).await else {
                    panic!("a known proven key with no token must not reach `{name}`");
                };
                assert_eq!(refused, miss, "the uniform refusal a stranger gets");
            }
        })
        .await;
}

/// A proven-only route cannot be opened to everyone, cannot sit behind an open base, and its handler
/// cannot be bound on a gated route: each is refused at assembly, naming why.
#[test]
fn proven_only_route_cannot_be_made_public() {
    let keys = Arc::new(Keys::default());
    let entered = Arc::new(Notify::new());
    let Err(public) = router(&keys, HashSet::new(), &entered)
        .public([svc(PICKUP)])
        .expose()
    else {
        panic!("a proven-only route named public must be refused");
    };
    assert!(
        public.to_string().contains("proven-only"),
        "the refusal names the proven-only route: {public}"
    );

    let Err(open) = Router::new(Gate::Open)
        .proven_service(
            svc(PICKUP),
            Hold {
                entered: Arc::clone(&entered),
            },
            |_| true,
        )
        .expect("`pickup` binds")
        .expose()
    else {
        panic!("a proven-only route under an open base must be refused");
    };
    assert!(
        open.to_string().contains("proven-only"),
        "the refusal names the proven-only route: {open}"
    );

    let gated = Router::new(Gate::rooted(signet().verifying_key(), Arc::clone(&keys)));
    let Err(bound) = gated.service(svc(PICKUP), Hold { entered }) else {
        panic!("a proven-only handler must not bind on a family route");
    };
    assert!(
        bound.to_string().contains("proven-only"),
        "the refusal names the handler: {bound}"
    );
}

/// A key the route does not know is refused before a slot is taken, so a stranger opening stream after
/// stream holds none of them, and a known key is still served in full.
#[tokio::test]
async fn a_stranger_flood_does_not_hold_a_proven_permit() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let keys = Arc::new(Keys::default());
            let entered = Arc::new(Notify::new());
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let known = HashSet::from([member.node_id().verify_key().expect("a checked key")]);
            let host = serve(router(&keys, known, &entered).expose().expect("assembles"));

            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let flood = stranger.connect(host).await.expect("connect");
            let mut refused = Vec::new();
            for _ in 0..PROVEN_STREAM_PERMITS * 2 {
                refused.push(ServiceStream::open(&flood, PICKUP).await.err());
            }
            assert!(
                refused
                    .iter()
                    .all(|refusal| *refusal == Some(Refusal::NotAdmitted)),
                "a key the route does not know is refused every time: {refused:?}"
            );

            let session = member.connect(host).await.expect("connect");
            let held = hold(&session, &entered, PROVEN_STREAM_PERMITS).await;
            assert_eq!(
                held.len(),
                PROVEN_STREAM_PERMITS,
                "the whole pool is the known key's"
            );
        })
        .await;
}

/// A full pool refuses the next known key with the uniform answer, identical to a miss.
#[tokio::test]
async fn a_full_proven_pool_answers_like_a_miss() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let keys = Arc::new(Keys::default());
            let entered = Arc::new(Notify::new());
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let known = HashSet::from([member.node_id().verify_key().expect("a checked key")]);
            let host = serve(router(&keys, known, &entered).expose().expect("assembles"));

            let session = member.connect(host).await.expect("connect");
            let _held = hold(&session, &entered, PROVEN_STREAM_PERMITS).await;
            let Err(full) = ServiceStream::open(&session, PICKUP).await else {
                panic!("the pool has {PROVEN_STREAM_PERMITS} slots and all are held");
            };
            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let stranger = stranger.connect(host).await.expect("connect");
            let Err(miss) = ServiceStream::open(&stranger, PICKUP).await else {
                panic!("a key the route does not know is refused");
            };
            assert_eq!(full, miss, "a full pool reads exactly like a miss");
        })
        .await;
}

/// A known peer that takes every slot and then never reads, never closes, and never lets the host close,
/// holds them only until the deadline: each stream is dropped then, and the pool serves again.
#[tokio::test(start_paused = true)]
async fn a_silent_proven_peer_releases_its_permit_by_the_deadline() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let keys = Arc::new(Keys::default());
            let entered = Arc::new(Notify::new());
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let known = HashSet::from([member.node_id().verify_key().expect("a checked key")]);
            let host = serve(router(&keys, known, &entered).expose().expect("assembles"));

            let session = member.connect(host).await.expect("connect");
            let admitted = tokio::time::Instant::now();
            let mut held = hold(&session, &entered, PROVEN_STREAM_PERMITS).await;

            tokio::time::sleep_until(
                admitted + PROVEN_STREAM_DEADLINE - Duration::from_millis(500),
            )
            .await;
            assert!(
                ServiceStream::open(&session, PICKUP).await.is_err(),
                "the held slots are still held before the deadline"
            );

            tokio::time::sleep_until(
                admitted + PROVEN_STREAM_DEADLINE + Duration::from_millis(500),
            )
            .await;
            let mut tail = Vec::new();
            let first = held.remove(0);
            let mut reader = first.reader;
            let ended =
                tokio::time::timeout(Duration::from_millis(100), reader.read_to_end(&mut tail))
                    .await;
            assert!(
                matches!(ended, Ok(Ok(_) | Err(_))),
                "the host dropped the stream at its deadline"
            );
            let _again = hold(&session, &entered, 1).await;
        })
        .await;
}

/// A proven-only admission is kept for the live cut by the key it was witnessed for, so revoking that key
/// ends the session at the next sweep, well before the stream's own deadline.
#[tokio::test]
async fn a_revoked_proven_peer_is_cut_mid_stream() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let keys = Arc::new(Keys::default());
            let entered = Arc::new(Notify::new());
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let key = member.node_id().verify_key().expect("a checked key");
            let exposer = router(&keys, HashSet::from([key]), &entered)
                .expose()
                .expect("assembles")
                .with_live_cuts(Arc::clone(&keys));
            let host = serve(exposer);

            let session = member.connect(host).await.expect("connect");
            let mut held = hold(&session, &entered, 1).await;
            keys.revoke(key);

            // One sweep, with room for a loaded box, and still well inside the deadline, which would
            // otherwise be what ended it.
            let within = PROVEN_STREAM_DEADLINE / 2;
            let mut byte = [0u8; 1];
            let ended = tokio::time::timeout(within, held[0].reader.read(&mut byte)).await;
            assert!(
                matches!(ended, Ok(Ok(0) | Err(_))),
                "a session on a proven key must end within a sweep of that key's revocation, not at \
                 its deadline"
            );
        })
        .await;
}

/// The recorded key is the one the cut asks about, and nothing else is kept: no id, root or anchor, and
/// no grant that could end the session by time.
#[test]
fn record_proven_keeps_the_key_and_nothing_else() {
    let key = Identity::from_secret(&[45u8; 32])
        .expect("valid secret")
        .verifying_key();
    let mut chains = AdmittedChains::default();
    chains.record_proven(key);
    assert_eq!(chains.peer(), Some(key));
    assert_eq!(chains.ids().count(), 0);
    assert_eq!(chains.roots().count(), 0);
    assert_eq!(chains.anchors().count(), 0);
    assert!(!chains.lapsed(std::time::SystemTime::now() + Duration::from_secs(3600 * 24 * 365)));
}

/// A store that answers "not revoked" and notes how many proven slots were free each time it was asked.
struct PoolWatch {
    pool: Arc<Semaphore>,
    free: Arc<Mutex<Vec<usize>>>,
}

impl Revocations for PoolWatch {
    fn is_revoked(&self, _cap: &Cap) -> bool {
        false
    }

    fn is_revoked_peer(&self, _peer: &VerifyKey) -> bool {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.pool.available_permits());
        false
    }
}

/// The key is checked before a slot is taken: while the gate's store and the route's `knows` rule on a
/// stream, every proven slot is still free, and the admitted stream holds exactly one after.
#[test]
fn a_proven_key_is_checked_before_a_slot_is_taken() {
    let keys = Arc::new(Keys::default());
    let pool = Arc::new(Semaphore::new(PROVEN_STREAM_PERMITS));
    let revoked_free = Arc::new(Mutex::new(Vec::new()));
    let known_free = Arc::new(Mutex::new(Vec::new()));
    let mut serving = serving_state(&keys, {
        let pool = Arc::clone(&pool);
        let free = Arc::clone(&known_free);
        move |_| {
            free.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(pool.available_permits());
            true
        }
    });
    serving.gate = Gate::rooted(
        signet().verifying_key(),
        PoolWatch {
            pool: Arc::clone(&pool),
            free: Arc::clone(&revoked_free),
        },
    );
    serving.proven_pool = Arc::clone(&pool);
    let peer = SessionPeer {
        node: NodeId::from_ed25519_secret(&[46u8; 32]),
        security: Security {
            peer: PeerProof::Proven,
            channel: ChannelProtection::Aead,
        },
    };
    let admitted = admit(
        Admission {
            gate: &serving.gate,
            public: &serving.public,
            public_unsafe: &serving.public_unsafe,
            pool: &serving.public_pool,
            proven: Proven {
                routes: &serving.services,
                pool: &serving.proven_pool,
            },
        },
        &PublicSession::default(),
        peer,
        None,
        None,
        &svc(PICKUP),
    )
    .expect("a known proven key is admitted");
    for (check, free) in [("the store", &revoked_free), ("`knows`", &known_free)] {
        let free = free.lock().unwrap_or_else(PoisonError::into_inner).clone();
        assert!(!free.is_empty(), "{check} rules on the stream");
        assert!(
            free.iter().all(|&free| free == PROVEN_STREAM_PERMITS),
            "{check} rules while every slot is free, not after one is taken: {free:?}"
        );
    }
    assert_eq!(pool.available_permits(), PROVEN_STREAM_PERMITS - 1);
    drop(admitted);
    assert_eq!(pool.available_permits(), PROVEN_STREAM_PERMITS);
}

/// Every service disabled.
struct NoneEnabled;

impl EnabledServices for NoneEnabled {
    fn is_enabled(&self, _service: &nauthy::Service) -> bool {
        false
    }
}

/// A writer that never takes a byte: a peer that gives the host no room to answer.
struct Stuck;

impl tokio::io::AsyncWrite for Stuck {
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

/// The deadline runs from admission to the end of the stream, refusals included: a known key that dials a
/// disabled proven-only route and never reads the refusal still gives its slot back by the deadline.
#[tokio::test(start_paused = true)]
async fn a_refusal_nobody_reads_frees_its_proven_slot_by_the_deadline() {
    use crate::protocol::Request;

    let keys = Arc::new(Keys::default());
    let mut serving = serving_state(&keys, |_| true);
    serving.enabled = Box::new(NoneEnabled);
    let serving = Arc::new(serving);
    let peer = SessionPeer {
        node: NodeId::from_ed25519_secret(&[47u8; 32]),
        security: Security {
            peer: PeerProof::Proven,
            channel: ChannelProtection::Aead,
        },
    };
    let (mut client, server) = tokio::io::duplex(1024);
    Request {
        service: PICKUP.to_owned(),
        capability: None,
        membership: None,
    }
    .write(&mut client)
    .await
    .expect("write request");

    let admitted = tokio::time::Instant::now();
    let served = tokio::spawn(super::serve_request(
        peer,
        Stuck,
        server,
        Arc::clone(&serving),
        Arc::new(PublicSession::default()),
        None,
    ));

    tokio::time::sleep_until(admitted + PROVEN_STREAM_DEADLINE - Duration::from_millis(500)).await;
    assert_eq!(
        serving.proven_pool.available_permits(),
        PROVEN_STREAM_PERMITS - 1,
        "the refused stream holds its slot while the refusal waits to be read"
    );

    tokio::time::sleep_until(admitted + PROVEN_STREAM_DEADLINE + Duration::from_millis(500)).await;
    assert!(
        served.is_finished(),
        "the stream is dropped at its deadline"
    );
    assert_eq!(
        serving.proven_pool.available_permits(),
        PROVEN_STREAM_PERMITS,
        "and its slot with it"
    );
    drop(client);
}
