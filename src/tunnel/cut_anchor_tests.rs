//! The live cut behind a gate whose trusted root can change: a session ends when a root it was anchored
//! at is no longer trusted, or when the key its peer proved is revoked, and a badge presented second is
//! never taken for an anchor. Also that an `Arc` over an oracle answers as the oracle does, and that an
//! oracle which keeps the defaults trusts every anchor.

use core::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::{Cap, Gate, Identity, IssuedIds, PinSource, RevocationId, Revocations, VerifyKey};

use super::super::{AdmittedChains, CUT_SWEEP, LiveCuts};
use super::{gated_echo, host_ends, hour, serve, signet, still_echoes, store};
use crate::identity::AsVerifyKey as _;
use crate::tunnel::Exposer;
use crate::tunnel::fixtures::{ServiceStream, prove, services, svc};
use crate::tunnel::router::{PublicRequest, PublicUnsafeRequest};

/// The root a node trusts when a test starts.
fn old_root() -> Identity {
    Identity::from_secret(&[21u8; 32]).expect("valid secret")
}

/// The root a test moves the pin to.
fn new_root() -> Identity {
    Identity::from_secret(&[22u8; 32]).expect("valid secret")
}

/// The serving machine's own key, which signs the slips it issues.
fn own() -> Identity {
    Identity::from_secret(&[23u8; 32]).expect("valid secret")
}

/// A pin a test can move while the node serves.
#[derive(Default)]
struct Pin(Mutex<Option<VerifyKey>>);

impl Pin {
    fn at(root: &Identity) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(root.verifying_key()))))
    }

    fn set(&self, root: &Identity) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(root.verifying_key());
    }
}

impl PinSource for Pin {
    fn current(&self) -> Option<VerifyKey> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The record of slips the own key issued.
#[derive(Clone, Default)]
struct Ledger(Arc<Mutex<HashSet<RevocationId>>>);

impl Ledger {
    /// Mint a slip for `service` under the own key and record it as issued.
    fn issue(&self, service: &str) -> Cap {
        let slip = own().mint(&svc(service), hour()).expect("mint slip");
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                slip.root_revocation_id()
                    .expect("a minted slip has a root id"),
            );
        slip
    }
}

impl IssuedIds for Ledger {
    fn is_issued(&self, id: &RevocationId) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(id)
    }
}

/// Revoked ids and revoked device keys, in memory, so a recall is seen at the next sweep.
#[derive(Default)]
struct Recalls {
    ids: Mutex<HashSet<RevocationId>>,
    keys: Mutex<HashSet<VerifyKey>>,
}

impl Recalls {
    fn revoke(&self, cap: &Cap) {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(cap.revocation_ids());
    }

    fn revoke_key(&self, key: VerifyKey) {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
    }

    fn names(&self, id: &RevocationId) -> bool {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(id)
    }
}

impl Revocations for Recalls {
    fn is_revoked(&self, cap: &Cap) -> bool {
        cap.revocation_ids().iter().any(|id| self.names(id))
    }

    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(peer)
    }
}

/// The oracle a caller whose pin moves wires: it cuts what the store recalls, trusts the pin as it
/// stands and its own key, and revokes the keys the store revokes.
struct PinnedCut {
    pin: Arc<Pin>,
    own: VerifyKey,
    recalls: Arc<Recalls>,
}

impl LiveCuts for PinnedCut {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        chains.ids().any(|id| self.recalls.names(id))
    }

    fn trusts(&self, anchor: &VerifyKey) -> bool {
        Some(*anchor) == self.pin.current() || *anchor == self.own
    }

    fn revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.recalls.is_revoked_peer(peer)
    }
}

/// An anchored node: its pin, its ledger, and its store, shared by the gate and the cut.
struct Anchored {
    pin: Arc<Pin>,
    ledger: Ledger,
    recalls: Arc<Recalls>,
}

impl Anchored {
    fn new() -> Self {
        Self {
            pin: Pin::at(&old_root()),
            ledger: Ledger::default(),
            recalls: Arc::default(),
        }
    }

    /// The oracle over this node's pin and store.
    fn cut(&self) -> PinnedCut {
        PinnedCut {
            pin: Arc::clone(&self.pin),
            own: own().verifying_key(),
            recalls: Arc::clone(&self.recalls),
        }
    }

    /// Two echo services behind the anchored gate, with the live cut wired to `oracle`.
    fn exposer(&self, oracle: impl LiveCuts + 'static) -> Exposer {
        prove(
            services(&["demo=echo:", "other=echo:"]),
            Gate::anchored(
                Arc::clone(&self.pin),
                own().verifying_key(),
                Arc::clone(&self.recalls),
                self.ledger.clone(),
            ),
            PublicRequest::none(),
            PublicUnsafeRequest::none(),
        )
        .expect("an anchored echo builds")
        .with_live_cuts(oracle)
    }
}

/// Open `service` on `session` presenting `cap`, and prove it echoes.
async fn open<S: bifrost::Session>(
    session: &S,
    service: &str,
    cap: &Cap,
) -> ServiceStream<S::Write, S::Read> {
    let mut stream = ServiceStream::open_with(
        session,
        service,
        Some(cap.link().expect("link").to_string()),
    )
    .await
    .expect("admitted");
    assert!(still_echoes(&mut stream).await, "served once admitted");
    stream
}

#[tokio::test]
async fn revoking_a_self_anchored_slip_cuts_its_live_session() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let node = Anchored::new();
            let host = serve(node.exposer(node.cut()));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let slip = node.ledger.issue("demo");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = open(&session, "demo", &slip).await;

            node.recalls.revoke(&slip);
            assert!(
                host_ends(&mut stream.reader).await,
                "a session admitted on a slip the own key issued ends once that slip is revoked"
            );
        })
        .await;
}

#[tokio::test]
async fn a_pin_change_cuts_sessions_of_the_old_root() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let node = Anchored::new();
            let host = serve(node.exposer(node.cut()));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = old_root()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = open(&session, "demo", &badge).await;

            node.pin.set(&new_root());
            assert!(
                host_ends(&mut stream.reader).await,
                "a session anchored at the old root ends once the pin moves"
            );
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_fleet_grant_session_survives_the_sweep() {
    // The two-token path: a slip the pinned root issued naming a fleet's root, and that root's badge for
    // the dialer. The fleet root is never the pin, so were the badge taken for an anchor the first sweep
    // would cut the session.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let node = Anchored::new();
            let host = serve(node.exposer(node.cut()));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let fleet = Identity::from_secret(&[24u8; 32]).expect("valid secret");
            let slip = old_root()
                .mint_authority_slip(&svc("demo"), fleet.verifying_key(), hour())
                .expect("mint slip");
            let badge = fleet
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint fleet badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = ServiceStream::open_with_slots(
                &session,
                "demo",
                Some(slip.link().expect("link").to_string()),
                Some(badge.link().expect("link").to_string()),
            )
            .await
            .expect("the fleet member is admitted");

            for sweep in 0..10 {
                tokio::time::sleep(CUT_SWEEP).await;
                assert!(
                    still_echoes(&mut stream).await,
                    "a fleet grant's session survives sweep {sweep}"
                );
            }
        })
        .await;
}

#[tokio::test]
async fn a_session_mixing_an_old_pin_stream_and_a_self_slip_is_cut_on_pin_change() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let node = Anchored::new();
            let host = serve(node.exposer(node.cut()));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = old_root()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");
            let slip = node.ledger.issue("other");

            let session = consumer.connect(host).await.expect("connect");
            let _pinned = open(&session, "demo", &badge).await;
            let mut own_slip = open(&session, "other", &slip).await;

            node.pin.set(&new_root());
            assert!(
                host_ends(&mut own_slip.reader).await,
                "a still-trusted anchor does not carry a session whose other anchor lost its trust"
            );
        })
        .await;
}

#[tokio::test]
async fn a_revoked_peer_key_cuts_its_open_session() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let node = Anchored::new();
            let host = serve(node.exposer(node.cut()));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = old_root()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");

            let session = consumer.connect(host).await.expect("connect");
            let mut stream = open(&session, "demo", &badge).await;

            node.recalls.revoke_key(consumer.node_id().verify_key());
            assert!(
                host_ends(&mut stream.reader).await,
                "a session whose peer key is revoked ends, though its badge is not"
            );
        })
        .await;
}

#[tokio::test]
async fn the_default_oracle_trusts_every_anchor() {
    // The oracle a rooted node wires keeps both defaults: whatever key it is asked about, it trusts the
    // anchor and revokes no peer, so a session nothing recalled keeps running.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (store, _roots, _denylist) = store("default-trust").await;
            for key in [
                signet().verifying_key(),
                old_root().verifying_key(),
                own().verifying_key(),
            ] {
                assert!(store.trusts(&key), "the default trusts every anchor");
                assert!(!store.revoked_peer(&key), "and revokes no peer");
            }

            let host = serve(gated_echo(&store));
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet()
                .mint_member(consumer.node_id().verify_key(), hour())
                .expect("mint badge");
            let session = consumer.connect(host).await.expect("connect");
            let mut stream = open(&session, "demo", &badge).await;

            tokio::time::sleep(CUT_SWEEP * 2 + Duration::from_millis(300)).await;
            assert!(
                still_echoes(&mut stream).await,
                "a session the default oracle rules on survives every sweep"
            );
        })
        .await;
}

/// An oracle with fixed answers, for proving what a wrapper around it forwards.
struct Fixed {
    trusts: bool,
    revoked_peer: bool,
}

impl LiveCuts for Fixed {
    fn cuts(&self, _chains: &AdmittedChains) -> bool {
        false
    }

    fn trusts(&self, _anchor: &VerifyKey) -> bool {
        self.trusts
    }

    fn revoked_peer(&self, _peer: &VerifyKey) -> bool {
        self.revoked_peer
    }
}

/// Serve a member session behind an anchored gate with the cut wired to `Arc<oracle>`, and report
/// whether the host ends it.
async fn arc_over(oracle: Fixed) -> bool {
    let node = Anchored::new();
    let host = serve(node.exposer(Arc::new(oracle)));
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    let badge = old_root()
        .mint_member(consumer.node_id().verify_key(), hour())
        .expect("mint badge");
    let session = consumer.connect(host).await.expect("connect");
    // No echo first: the oracle rules against the session from the first sweep, which may come before it.
    let mut stream = ServiceStream::open_with(
        &session,
        "demo",
        Some(badge.link().expect("link").to_string()),
    )
    .await
    .expect("admitted");
    host_ends(&mut stream.reader).await
}

#[tokio::test]
async fn arc_live_cuts_forwards_trusts() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            assert!(
                arc_over(Fixed {
                    trusts: false,
                    revoked_peer: false,
                })
                .await,
                "an Arc over an oracle that trusts no anchor cuts as the oracle does"
            );
        })
        .await;
}

#[tokio::test]
async fn arc_live_cuts_forwards_revoked_peer() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            assert!(
                arc_over(Fixed {
                    trusts: true,
                    revoked_peer: true,
                })
                .await,
                "an Arc over an oracle that revokes the peer cuts as the oracle does"
            );
        })
        .await;
}
