//! The live cut, end to end over the in-process transport: a session admitted on a capability that is
//! recalled afterwards ends itself within a sweep, a session nothing recalled keeps running, and a node
//! with the cut wired still frees every closed session's slot.

use core::time::Duration;
use std::path::PathBuf;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::{DisabledRoots, FileDenylist, Gate, Identity, Latch};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::exposer::MAX_SESSIONS;
use super::super::fixtures::{ServiceStream, prove, services, svc};
use super::super::router::{PublicRequest, PublicUnsafeRequest};
use super::{AdmittedChains, CUT_SWEEP, LiveCuts};
use crate::identity::AsVerifyKey as _;
use crate::tunnel::{CancellationToken, Exposer};

/// Long enough for a sweep and the store's refresh debounce with room for a loaded CI box, short enough
/// that a cut that never comes fails the suite rather than hanging it.
const WITHIN: Duration = Duration::from_secs(5);

/// A unique scratch path per test, with every sibling a store writes cleared first.
fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("tb-cut-{tag}-{}", std::process::id()));
    for suffix in ["", ".lock", ".written"] {
        let mut sibling = path.clone().into_os_string();
        sibling.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(sibling));
    }
    path
}

/// The signet every gated test roots at.
fn signet() -> Identity {
    Identity::from_secret(&[9u8; 32]).expect("valid secret")
}

/// An hour out: nothing here expires mid-test.
fn hour() -> std::time::SystemTime {
    nauthy::Request::expires_in(Duration::from_secs(3600))
}

/// The one store both the gate and the cut read, as a product caller composes it.
async fn store(tag: &str) -> (Arc<Latch<FileDenylist>>, PathBuf, PathBuf) {
    let roots = scratch(&format!("{tag}-roots"));
    let denylist = scratch(&format!("{tag}-deny"));
    let store = Latch::new(
        DisabledRoots::load(roots.clone())
            .await
            .expect("load roots"),
        FileDenylist::load(denylist.clone())
            .await
            .expect("load denylist"),
    );
    (Arc::new(store), roots, denylist)
}

/// A gated echo exposer over `store`, with the live cut wired to the same instance.
fn gated_echo(store: &Arc<Latch<FileDenylist>>) -> Exposer {
    prove(
        services(&["demo=echo:"]),
        Gate::rooted(signet().verifying_key(), Arc::clone(store)),
        PublicRequest::none(),
        PublicUnsafeRequest::none(),
    )
    .expect("a gated echo builds")
    .with_live_cuts(Arc::clone(store))
}

/// Bind the exposer on its own node and serve it for the rest of the test.
fn serve(exposer: Exposer) -> bifrost::NodeId {
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

/// Whether a stream left open, and never half-closed by us, is ended by the host within [`WITHIN`].
async fn host_ends<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(WITHIN, reader.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// Round-trip one byte through the echo, proving the stream is still served.
async fn still_echoes<W, R>(stream: &mut ServiceStream<W, R>) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    if stream.writer.write_all(b"?").await.is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(WITHIN, stream.reader.read(&mut byte)).await,
        Ok(Ok(1))
    )
}

#[tokio::test]
async fn a_session_is_cut_when_a_cap_it_was_admitted_on_is_revoked() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, denylist) = store("revoked").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the member is admitted");
            assert!(still_echoes(&mut stream).await, "served before the recall");

            // Revoked by another writer on the same file, as `revoke` would from another process.
            let mut writer = FileDenylist::empty(denylist.clone());
            writer.revoke(&badge).await.expect("revoke the badge");

            assert!(
                host_ends(&mut stream.reader).await,
                "a session admitted on a revoked cap must end within a sweep, not run on"
            );
        })
        .await;
}

#[tokio::test]
async fn a_session_is_cut_when_the_root_it_was_admitted_under_is_disabled() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, roots, _denylist) = store("disabled").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the member is admitted");
            assert!(still_echoes(&mut stream).await, "served before the disable");

            let mut writer = DisabledRoots::open_for_repair(roots.clone());
            writer
                .disable(signet().verifying_key())
                .await
                .expect("disable the root");

            assert!(
                host_ends(&mut stream.reader).await,
                "a session admitted under a root since disabled must end within a sweep"
            );
        })
        .await;
}

#[tokio::test]
async fn a_session_admitted_through_a_foreign_badge_is_cut_when_that_root_is_disabled() {
    // The two-token path: a slip this node issued, naming a foreign authority, and that authority's badge
    // for the dialer. The gate refuses a disabled foreign root at admission, so the cut must too.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, roots, _denylist) = store("foreign").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let foreign = Identity::from_secret(&[11u8; 32]).expect("valid secret");
            let slip = signet()
                .mint_authority_slip(&svc("demo"), foreign.verifying_key(), hour())
                .expect("mint slip");
            let badge = foreign
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint foreign badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with_slots(
                &session,
                "demo",
                Some(slip.link().expect("link").to_string()),
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the foreign member is admitted");
            assert!(still_echoes(&mut stream).await, "served before the disable");

            let mut writer = DisabledRoots::open_for_repair(roots.clone());
            writer
                .disable(foreign.verifying_key())
                .await
                .expect("disable the foreign root");

            assert!(
                host_ends(&mut stream.reader).await,
                "a session admitted on a foreign badge must end once that badge's root is disabled"
            );
        })
        .await;
}

#[tokio::test]
async fn a_session_nothing_recalled_keeps_running_across_sweeps() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, denylist) = store("survives").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");
            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the member is admitted");

            // Some OTHER grant is revoked: the cut is keyed on this session's chains, not on the file.
            let unrelated = signet().mint(&svc("demo"), hour()).expect("mint slip");
            let mut writer = FileDenylist::empty(denylist.clone());
            writer
                .revoke(&unrelated)
                .await
                .expect("revoke another grant");

            tokio::time::sleep(CUT_SWEEP * 2 + Duration::from_millis(300)).await;
            assert!(
                still_echoes(&mut stream).await,
                "a session whose own chains are clean survives every sweep"
            );
        })
        .await;
}

#[tokio::test]
async fn closed_sessions_free_their_slots_with_the_cut_wired() {
    // Every connect-and-close must end its session. Past `MAX_SESSIONS` closed sessions still held, the
    // exposer stops accepting and the next dial is never answered, so this runs one cycle past the cap.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let exposer = prove(
                services(&["demo=echo:"]),
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none(),
            )
            .expect("an open echo builds")
            .with_live_cuts(FileDenylist::empty(scratch("wedge")));
            let host = serve(exposer);
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            // The run's first sweep fires at once; let it, so every session below has one to see.
            tokio::time::sleep(Duration::from_millis(50)).await;

            for cycle in 0..=MAX_SESSIONS {
                let session = consumer.connect(host).await.expect("connect");
                let answered = tokio::time::timeout(WITHIN, async {
                    let mut stream = ServiceStream::open(&session, "demo")
                        .await
                        .expect("an open echo admits");
                    stream.writer.shutdown().await.expect("half-close");
                    let mut rest = Vec::new();
                    stream
                        .reader
                        .read_to_end(&mut rest)
                        .await
                        .expect("read to end");
                })
                .await;
                assert!(
                    answered.is_ok(),
                    "cycle {cycle} was never answered: closed sessions are holding their slots"
                );
                drop(session);
                // A sweep between cycles is what would park a closed session that is not guarded.
                if cycle % 64 == 0 {
                    tokio::time::sleep(CUT_SWEEP + Duration::from_millis(100)).await;
                }
            }
        })
        .await;
}

#[tokio::test]
async fn the_latch_cuts_on_a_kept_root_or_a_kept_id_and_nothing_else() {
    let (store, roots, denylist) = store("oracle").await;
    let clean = signet().mint(&svc("demo"), hour()).expect("mint");
    let revoked = signet().mint(&svc("web"), hour()).expect("mint");
    let foreign = Identity::from_secret(&[12u8; 32]).expect("valid secret");
    let foreign_cap = foreign.mint(&svc("demo"), hour()).expect("mint");

    let kept = |cap: &nauthy::Cap| {
        let mut chains = AdmittedChains::default();
        chains.record(cap);
        chains
    };
    assert!(
        !store.cuts(&AdmittedChains::default()),
        "nothing kept, nothing cut"
    );
    assert!(!store.cuts(&kept(&clean)), "a clean chain is not cut");

    FileDenylist::empty(denylist.clone())
        .revoke(&revoked)
        .await
        .expect("revoke");
    DisabledRoots::open_for_repair(roots.clone())
        .disable(foreign.verifying_key())
        .await
        .expect("disable");
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(store.cuts(&kept(&revoked)), "a kept revoked id is cut");
    assert!(
        store.cuts(&kept(&foreign_cap)),
        "a kept disabled root is cut"
    );
    assert!(!store.cuts(&kept(&clean)), "the clean chain still is not");
}

#[tokio::test]
async fn a_session_is_refused_streams_past_its_chain_ceiling() {
    // A holder re-attenuates one badge per stream: each copy carries fresh ids that still admit. Past the
    // ceiling the session is refused the stream rather than grown, and a cap it already holds still admits.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("ceiling").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");
            let session = consumer.connect(host).await.expect("connect");

            // Eight fresh blocks per copy, so the ceiling is reached in about 128 streams.
            let fresh_copy = || {
                (0..8).fold(badge.clone(), |cap, _| {
                    cap.attenuate(None, Some(hour())).expect("attenuate")
                })
            };
            let mut admitted = 0usize;
            let mut refused = None;
            for stream in 0..(2 * super::MAX_SESSION_CHAIN_IDS / 8) {
                let copy = fresh_copy().link().expect("link").to_string();
                match ServiceStream::open_with(&session, "demo", Some(copy)).await {
                    Ok(_) => admitted += 1,
                    Err(refusal) => {
                        refused = Some((stream, refusal));
                        break;
                    }
                }
            }
            let (at, refusal) =
                refused.expect("a session past its ceiling must be refused, not grown");
            assert_eq!(
                refusal,
                bifrost::Refusal::NotAdmitted,
                "the uniform refusal"
            );
            assert!(
                admitted * 8 <= super::MAX_SESSION_CHAIN_IDS && at == admitted,
                "refused at the ceiling, not before it: {admitted} admitted"
            );
            assert!(
                ServiceStream::open_with(
                    &session,
                    "demo",
                    Some(badge.link().expect("link").to_string())
                )
                .await
                .is_ok(),
                "a cap the session already keeps adds nothing and still admits"
            );
        })
        .await;
}

#[test]
fn a_refused_record_keeps_nothing() {
    // Fill the record to the ceiling exactly, one id per grant; the next is refused whole and the record
    // is unchanged, while a grant already kept is still accepted.
    let caps: Vec<nauthy::Cap> = (0..=super::MAX_SESSION_CHAIN_IDS)
        .map(|_| signet().mint(&svc("demo"), hour()).expect("mint"))
        .collect();
    let (fill, over) = caps.split_at(super::MAX_SESSION_CHAIN_IDS);
    let mut chains = AdmittedChains::default();
    for cap in fill {
        chains
            .record_all(core::slice::from_ref(cap))
            .expect("under the ceiling");
    }
    assert!(
        chains.record_all(over).is_err(),
        "one past the ceiling is refused"
    );
    assert_eq!(
        chains.len(),
        super::MAX_SESSION_CHAIN_IDS,
        "and keeps nothing of it"
    );
    assert!(
        chains.record_all(&fill[..1]).is_ok(),
        "a grant already kept adds nothing and is accepted"
    );
}

/// A mem session that records whether it was closed, so a test can tell a cut that ENDS the session from
/// one that only drops it.
struct Closing {
    inner: bifrost_mem::MemSession,
    closed: Arc<core::sync::atomic::AtomicBool>,
}

impl bifrost::Session for Closing {
    type Security = <bifrost_mem::MemSession as bifrost::Session>::Security;
    type Write = <bifrost_mem::MemSession as bifrost::Session>::Write;
    type Read = <bifrost_mem::MemSession as bifrost::Session>::Read;

    fn peer(&self) -> bifrost::NodeId {
        self.inner.peer()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.inner.open_bi().await
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.inner.accept_bi().await
    }

    async fn wait_closed(&self) {
        self.inner.wait_closed().await;
    }

    fn close(&self) {
        self.closed
            .store(true, core::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_cut_closes_the_session_rather_than_only_dropping_it() {
    // A transport can keep a connection open while a detached task holds one of its streams, so the cut
    // must close the session explicitly.
    use bifrost::Transport as _;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, denylist) = store("close").await;
            let serving = Arc::new(super::super::exposer::Serving {
                gate: Gate::rooted(signet().verifying_key(), Arc::clone(&store)),
                public: super::super::router::PublicServices::default(),
                public_unsafe: super::super::router::PublicServices::default(),
                services: services(&["demo=echo:"]),
                raw_stream_opens: tokio::sync::Semaphore::new(4),
                public_pool: super::super::exposer::PublicPool::new(),
                enabled: Box::new(crate::enabled::AllEnabled),
                cuts: Some(super::Cuts::new(Box::new(Arc::clone(&store)))),
            });
            let host = MemTransport::bind();
            let consumer = MemTransport::bind();
            let dialed = consumer
                .connect(bifrost::Addr::from_node(host.node_id()))
                .await
                .expect("connect");
            let closed = Arc::new(core::sync::atomic::AtomicBool::new(false));
            let accepted = Closing {
                inner: host.accept().await.expect("accept"),
                closed: Arc::clone(&closed),
            };
            let session = tokio::task::spawn_local(super::super::exposer::serve_session(
                accepted,
                Arc::clone(&serving),
            ));
            let sweeper = tokio::task::spawn_local({
                let serving = Arc::clone(&serving);
                async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        if let Some(cuts) = &serving.cuts {
                            cuts.sweep();
                        }
                    }
                }
            });

            let badge = signet()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");
            let _stream = ServiceStream::open_with(
                &dialed,
                "demo",
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the member is admitted");
            FileDenylist::empty(denylist.clone())
                .revoke(&badge)
                .await
                .expect("revoke");

            tokio::time::timeout(WITHIN, session)
                .await
                .expect("the session is cut")
                .expect("the session task joins")
                .expect("a cut is a clean return");
            sweeper.abort();
            assert!(
                closed.load(core::sync::atomic::Ordering::SeqCst),
                "the cut closed the session, not just dropped it"
            );
        })
        .await;
}
