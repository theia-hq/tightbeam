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

/// A grant that runs out mid-test: long enough to be admitted and echo once, short enough that its
/// expiry plus a sweep lands well inside [`WITHIN`].
const SHORT: Duration = Duration::from_secs(2);

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

/// The key a unit test's streams were admitted from.
fn dialer() -> nauthy::VerifyKey {
    Identity::from_secret(&[13u8; 32])
        .expect("valid secret")
        .verifying_key()
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
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
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
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
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
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
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
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
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
async fn a_session_is_cut_once_the_grant_it_was_admitted_on_expires() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("expired").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    nauthy::Request::expires_in(SHORT),
                )
                .expect("mint badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the member is admitted");
            assert!(still_echoes(&mut stream).await, "served before the expiry");

            // Nothing is revoked or disabled: only the clock moves.
            assert!(
                host_ends(&mut stream.reader).await,
                "a session must not outlive the only grant it was admitted on"
            );
        })
        .await;
}

#[tokio::test]
async fn a_session_is_cut_at_a_narrowed_expiry_not_the_issuers() {
    // The holder narrowed an hour-long badge to seconds and passed it on. The session admitted on it must
    // end at the narrower instant: the chain's earliest bound, not the one the signet signed.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("narrowed").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let narrowed = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
                .expect("mint badge")
                .attenuate(None, Some(nauthy::Request::expires_in(SHORT)))
                .expect("narrow the badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(narrowed.link().expect("link").to_string()),
            )
            .await
            .expect("the narrowed badge is admitted");
            assert!(still_echoes(&mut stream).await, "served before the expiry");

            assert!(
                host_ends(&mut stream.reader).await,
                "a session must end at the narrowed expiry, not run on to the issuer's"
            );
        })
        .await;
}

/// `cap` with `datalog` appended as a block, the way a holder narrows a cap outside nauthy's own API:
/// decode the link, append with biscuit's block builder (no secret needed), and encode it again.
fn with_raw_block(cap: &nauthy::Cap, datalog: &str) -> nauthy::Cap {
    with_block(
        cap,
        biscuit_auth::builder::BlockBuilder::new()
            .code(datalog)
            .expect("datalog"),
    )
}

/// `cap` with `block` appended, the same way as [`with_raw_block`], for a block datalog text cannot
/// spell (a date past RFC 3339's range, set through a parameter).
fn with_block(cap: &nauthy::Cap, block: biscuit_auth::builder::BlockBuilder) -> nauthy::Cap {
    use data_encoding::BASE32_NOPAD;

    let link = cap.link().expect("link").to_string();
    let (root, token) = link.split_once('.').expect("a link is root.token");
    let token = biscuit_auth::UnverifiedBiscuit::from(
        BASE32_NOPAD
            .decode(token.to_ascii_uppercase().as_bytes())
            .expect("base32"),
    )
    .expect("a token")
    .append(block)
    .expect("append")
    .to_vec()
    .expect("encode");
    let link = format!("{root}.{}", BASE32_NOPAD.encode(&token).to_lowercase());
    nauthy::Cap::parse(&link).expect("the appended cap still verifies")
}

#[tokio::test]
async fn a_stream_on_a_cap_whose_expiry_cannot_be_read_is_refused() {
    // The gate admits this badge: its extra check (`<` rather than `<=`) passes now. But the cut cannot
    // read when it ends, so it treats it as already expired and the stream is refused, never served on
    // a lease nothing bounds.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("unreadable").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
                .expect("mint badge");
            let odd = with_raw_block(&badge, "check if time($t), $t < 2100-01-01T00:00:00Z;");
            assert!(
                matches!(odd.valid_until(), Err(nauthy::CapError::UnreadableExpiry)),
                "the fixture is a cap whose expiry cannot be read"
            );

            let session = consumer.connect(host).await.expect("connect");
            assert!(
                ServiceStream::open_with(
                    &session,
                    "demo",
                    Some(odd.link().expect("link").to_string())
                )
                .await
                .is_err(),
                "a stream on an unreadable expiry is refused"
            );
            // The same badge without the odd block is admitted on the same session: only the read
            // refused it.
            assert!(
                ServiceStream::open_with(
                    &session,
                    "demo",
                    Some(badge.link().expect("link").to_string())
                )
                .await
                .is_ok(),
                "the plain badge is admitted"
            );
        })
        .await;
}

#[tokio::test]
async fn a_stream_on_a_clock_bound_past_the_clocks_range_is_refused_and_the_node_serves_on() {
    // A holder appends `check if time($t), $t <= Date(u64::MAX)` to a badge the gate admits. Reading
    // that date once panicked inside the admission path, on the one task that runs the whole exposer,
    // so one stream took the node down for everyone. It must be refused like any unreadable expiry, and
    // the node must go on serving other peers.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("far-date").await;
            let host = serve(gated_echo(&store));
            let hostile = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(
                    hostile.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
                .expect("mint badge");
            let far = with_block(
                &badge,
                biscuit_auth::builder::BlockBuilder::new()
                    .code_with_params(
                        "check if time($t), $t <= {bound};",
                        std::collections::HashMap::from([(
                            "bound".to_owned(),
                            biscuit_auth::builder::Term::Date(u64::MAX),
                        )]),
                        std::collections::HashMap::new(),
                    )
                    .expect("datalog"),
            );

            let session = hostile.connect(host).await.expect("connect");
            assert!(
                ServiceStream::open_with(
                    &session,
                    "demo",
                    Some(far.link().expect("link").to_string())
                )
                .await
                .is_err(),
                "a stream on a date past the clock's range is refused"
            );

            // Another peer, on a fresh session, is still served: the node did not go down.
            let other = Node::new(MemTransport::bind(), NoDiscovery);
            let plain = signet()
                .mint_member(other.node_id().verify_key().expect("a checked key"), hour())
                .expect("mint badge");
            let session = other.connect(host).await.expect("the node still accepts");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(plain.link().expect("link").to_string()),
            )
            .await
            .expect("the node still admits");
            assert!(still_echoes(&mut stream).await, "the node still serves");
        })
        .await;
}

#[tokio::test]
async fn a_session_ends_when_the_first_grant_it_was_admitted_on_runs_out() {
    // Two streams on one session, one on a grant that expires and one on a grant that lasts. The cut is
    // session-granular and takes the earliest grant, so the lasting stream ends with the brief one.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("first-out").await;
            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let brief = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    nauthy::Request::expires_in(SHORT),
                )
                .expect("mint the short badge");
            let lasting = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
                .expect("mint the lasting badge");

            let session = consumer.connect(host).await.expect("connect");
            let _short = ServiceStream::open_with(
                &session,
                "demo",
                Some(brief.link().expect("link").to_string()),
            )
            .await
            .expect("admitted on the short badge");
            let mut long = ServiceStream::open_with(
                &session,
                "demo",
                Some(lasting.link().expect("link").to_string()),
            )
            .await
            .expect("admitted on the lasting badge");
            assert!(still_echoes(&mut long).await, "served before the expiry");

            assert!(
                host_ends(&mut long.reader).await,
                "a session ends when the first grant it was admitted on runs out"
            );
        })
        .await;
}

/// A gated exposer with two echo services, so one session can hold grants for different names.
fn gated_pair(store: &Arc<Latch<FileDenylist>>) -> Exposer {
    prove(
        services(&["demo=echo:", "other=echo:"]),
        Gate::rooted(signet().verifying_key(), Arc::clone(store)),
        PublicRequest::none(),
        PublicUnsafeRequest::none(),
    )
    .expect("a gated pair builds")
    .with_live_cuts(Arc::clone(store))
}

#[tokio::test]
async fn a_short_grant_is_not_carried_past_its_expiry_by_a_later_grant_for_another_service() {
    // The attack: a short slip for `demo`, and any later-expiring slip from the same root for another
    // name. The `demo` stream must end when its own slip does, not ride the later one.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("carried").await;
            let host = serve(gated_pair(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let short = signet()
                .mint(&svc("demo"), nauthy::Request::expires_in(SHORT))
                .expect("mint the short slip");
            let later = signet()
                .mint(&svc("other"), hour())
                .expect("mint the later slip");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(short.link().expect("link").to_string()),
            )
            .await
            .expect("admitted to demo on the short slip");
            let _anchor = ServiceStream::open_with(
                &session,
                "other",
                Some(later.link().expect("link").to_string()),
            )
            .await
            .expect("admitted to other on the later slip");
            assert!(still_echoes(&mut stream).await, "served before the expiry");

            assert!(
                host_ends(&mut stream.reader).await,
                "a stream must not outlive its own grant on the strength of a later one"
            );
        })
        .await;
}

#[tokio::test]
async fn a_stream_refused_after_the_gate_does_not_hold_a_session_open() {
    // A whole-node badge passes the gate for any name, and a name the node does not expose is refused
    // only after it. That refused stream's later grant must not keep the short one's session alive.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("refused-holds").await;
            let host = serve(gated_pair(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let short = signet()
                .mint(&svc("demo"), nauthy::Request::expires_in(SHORT))
                .expect("mint the short slip");
            let lasting = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
                .expect("mint the lasting badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(short.link().expect("link").to_string()),
            )
            .await
            .expect("admitted to demo on the short slip");
            assert!(
                ServiceStream::open_with(
                    &session,
                    "absent",
                    Some(lasting.link().expect("link").to_string())
                )
                .await
                .is_err(),
                "a name the node does not expose is refused past the gate"
            );

            assert!(
                host_ends(&mut stream.reader).await,
                "a refused stream's grant must not hold the session open"
            );
        })
        .await;
}

#[tokio::test]
async fn a_stream_refused_after_the_gate_leaves_the_session_lease_untouched() {
    // The mirror of the test above: a refused stream on a SHORTER grant must not end a session its own
    // grant never bounded. Only a stream admission wholly passed shapes the lease.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("refused-untouched").await;
            let host = serve(gated_pair(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let lasting = signet()
                .mint(&svc("demo"), hour())
                .expect("mint the lasting slip");
            let brief = signet()
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    nauthy::Request::expires_in(SHORT),
                )
                .expect("mint the short badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(lasting.link().expect("link").to_string()),
            )
            .await
            .expect("admitted to demo on the lasting slip");
            assert!(
                ServiceStream::open_with(
                    &session,
                    "absent",
                    Some(brief.link().expect("link").to_string())
                )
                .await
                .is_err(),
                "a name the node does not expose is refused past the gate"
            );

            tokio::time::sleep(SHORT + CUT_SWEEP * 2).await;
            assert!(
                still_echoes(&mut stream).await,
                "a refused stream's grant must not bound the session"
            );
        })
        .await;
}

#[tokio::test]
async fn a_raw_stream_whose_open_is_refused_leaves_the_session_lease_untouched() {
    // Admission passes and only the open fails: the target is a directory, which a raw stream refuses.
    // Nothing was served, so that stream's shorter grant must not end the session.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("open-refused").await;
            let directory = std::env::temp_dir();
            let host = serve(
                prove(
                    services(&["demo=echo:", &format!("dir=file:{}", directory.display())]),
                    Gate::rooted(signet().verifying_key(), Arc::clone(&store)),
                    PublicRequest::none(),
                    PublicUnsafeRequest::none(),
                )
                .expect("an echo and a raw stream build")
                .with_live_cuts(Arc::clone(&store)),
            );
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let lasting = signet()
                .mint(&svc("demo"), hour())
                .expect("mint the lasting slip");
            let brief = signet()
                .mint(&svc("dir"), nauthy::Request::expires_in(SHORT))
                .expect("mint the short slip");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with(
                &session,
                "demo",
                Some(lasting.link().expect("link").to_string()),
            )
            .await
            .expect("admitted to demo on the lasting slip");
            assert!(
                matches!(
                    ServiceStream::open_with(
                        &session,
                        "dir",
                        Some(brief.link().expect("link").to_string())
                    )
                    .await,
                    Err(bifrost::Refusal::Unavailable { .. })
                ),
                "a directory is admitted past the gate and refused at the open"
            );

            tokio::time::sleep(SHORT + CUT_SWEEP * 2).await;
            assert!(
                still_echoes(&mut stream).await,
                "a stream refused at its open must not bound the session"
            );
        })
        .await;
}

/// A whole second far in the future, so a grant minted for it states exactly this instant.
fn at(secs: u64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000 + secs)
}

#[test]
fn a_stream_reads_its_earliest_expiry_and_fails_closed_on_an_unreadable_one() {
    use nauthy::CapError;

    use super::Lease;

    // None: a stream ruled on no cap, or on caps that never expire, has no bound.
    assert_eq!(Lease::earliest([]).ok(), Some(None));
    assert_eq!(Lease::earliest([Ok(None), Ok(None)]).ok(), Some(None));
    // Many: the earliest bound any cap sets, whatever the order; a cap that never expires adds none.
    assert_eq!(
        Lease::earliest([Ok(Some(at(30))), Ok(None), Ok(Some(at(10)))]).ok(),
        Some(Some(at(10)))
    );
    // Error: one unreadable expiry fails the whole stream, before or after a readable one, and is never
    // read as "no bound".
    for reads in [
        [Ok(Some(at(10))), Err(CapError::UnreadableExpiry)],
        [Err(CapError::UnreadableExpiry), Ok(None)],
    ] {
        assert!(
            matches!(Lease::earliest(reads), Err(CapError::UnreadableExpiry)),
            "an unreadable expiry is treated as expired"
        );
    }
}

#[test]
fn a_lease_lapses_at_the_first_grant_of_any_stream() {
    use super::Lease;

    // None: a session no stream was admitted on a grant never lapses.
    assert!(!AdmittedChains::default().lapsed(at(1_000_000)));

    // One: good through its expiry instant, lapsed strictly after.
    let mut one = AdmittedChains::default();
    one.record(&signet().mint(&svc("demo"), at(10)).expect("mint"));
    assert!(!one.lapsed(at(10)), "a grant is good through its expiry");
    assert!(one.lapsed(at(11)), "and lapsed after it");
    one.record_all(dialer(), &[])
        .expect("an open stream keeps nothing");
    assert!(
        one.lapsed(at(11)),
        "an open stream, ruled on nothing, holds no session open"
    );

    // Many streams: the session ends at the FIRST grant to run out, in whichever order they came.
    let mut many = AdmittedChains::default();
    for secs in [20, 30, 10] {
        many.record(&signet().mint(&svc("demo"), at(secs)).expect("mint"));
    }
    assert!(!many.lapsed(at(10)), "held through the earliest grant");
    assert!(many.lapsed(at(11)), "lapsed once any grant has");

    // A grant that never expires bounds nothing: the session is unbounded only when every grant is, and
    // otherwise ends at its bounded grants' earliest, whichever came first.
    let never = Lease::default().extend(None);
    assert_eq!(
        never,
        Lease::Unbounded,
        "one unbounded grant bounds nothing"
    );
    assert_eq!(never.extend(None), Lease::Unbounded, "nor do two");
    assert_eq!(never.extend(Some(at(10))), Lease::Until(at(10)));
    assert_eq!(
        Lease::default().extend(Some(at(10))).extend(None),
        Lease::Until(at(10))
    );

    // One stream ruled on two caps needed both, so its grant ends at the EARLIER.
    let foreign = Identity::from_secret(&[11u8; 32]).expect("valid secret");
    let slip = signet()
        .mint_authority_slip(&svc("demo"), foreign.verifying_key(), at(40))
        .expect("mint slip");
    let badge = foreign
        .mint_member(signet().verifying_key(), at(15))
        .expect("mint badge");
    let mut paired = AdmittedChains::default();
    paired
        .record_all(dialer(), &[slip, badge])
        .expect("under the ceiling");
    assert!(!paired.lapsed(at(15)), "held while both caps hold");
    assert!(
        paired.lapsed(at(16)),
        "a stream that needed both caps ends with the first to expire"
    );
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
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
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
            .record_all(dialer(), core::slice::from_ref(cap))
            .expect("under the ceiling");
    }
    assert!(
        chains.record_all(dialer(), over).is_err(),
        "one past the ceiling is refused"
    );
    assert_eq!(
        chains.len(),
        super::MAX_SESSION_CHAIN_IDS,
        "and keeps nothing of it"
    );
    assert!(
        chains.record_all(dialer(), &fill[..1]).is_ok(),
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
                proven_pool: Arc::new(tokio::sync::Semaphore::new(
                    super::super::exposer::PROVEN_STREAM_PERMITS,
                )),
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
                .mint_member(
                    consumer.node_id().verify_key().expect("a checked key"),
                    hour(),
                )
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

/// A mem transport whose `accept` spends [`Handshaking::TAKES`] after taking a connection, as a real
/// transport's handshake does inside `accept`. Dropping the future mid-wait drops the connection with it,
/// which is exactly what a real handshake cut short does to its dialer.
struct Handshaking(MemTransport);

impl Handshaking {
    /// Longer than a sweep, so every handshake straddles a tick.
    const TAKES: Duration = Duration::from_millis(1500);
}

const _: () = assert!(Handshaking::TAKES.as_millis() > CUT_SWEEP.as_millis());

impl bifrost::Transport for Handshaking {
    type Security = <MemTransport as bifrost::Transport>::Security;
    type Session = <MemTransport as bifrost::Transport>::Session;

    fn node_id(&self) -> bifrost::NodeId {
        self.0.node_id()
    }

    fn local_addr(&self) -> bifrost::Addr {
        self.0.local_addr()
    }

    fn bound_sockets(&self) -> Vec<core::net::SocketAddr> {
        self.0.bound_sockets()
    }

    async fn connect(&self, addr: bifrost::Addr) -> Result<Self::Session, bifrost::Error> {
        self.0.connect(addr).await
    }

    async fn accept(&self) -> Result<Self::Session, bifrost::Error> {
        let session = self.0.accept().await?;
        tokio::time::sleep(Self::TAKES).await;
        Ok(session)
    }

    async fn close(&self) {
        self.0.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_handshake_in_flight_across_a_sweep_is_still_accepted() {
    // The sweep ticks while `accept` is mid-handshake. The loop must carry that handshake across the
    // tick; one that rebuilds `accept` each turn drops it, and the dialer holds a session nobody serves.
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
            .with_live_cuts(FileDenylist::empty(scratch("handshake")));
            let node = Node::new(Handshaking(MemTransport::bind()), NoDiscovery);
            let host = node.node_id();
            tokio::task::spawn_local(async move {
                exposer
                    .run(&node, CancellationToken::new())
                    .await
                    .expect("exposer runs");
            });
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);

            for dial in 0..3 {
                let session = consumer.connect(host).await.expect("connect");
                let served = tokio::time::timeout(WITHIN, async {
                    let mut stream = ServiceStream::open(&session, "demo").await.ok()?;
                    still_echoes(&mut stream).await.then_some(())
                })
                .await;
                assert!(
                    matches!(served, Ok(Some(()))),
                    "dial {dial} was dropped mid-handshake by a sweep tick"
                );
            }
        })
        .await;
}

#[path = "cut_anchor_tests.rs"]
mod anchors;
