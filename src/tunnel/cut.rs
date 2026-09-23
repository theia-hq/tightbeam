//! The live cut: a session admitted on a capability that is later recalled ends itself, rather than
//! running on until its peer leaves.
//!
//! Admission rules per stream, at the moment the stream opens, so a recall written after that moment has
//! no stream left to refuse. The cut closes that gap without a registry of who is connected: each session
//! keeps the chains it was admitted on, in its own frame, and re-asks the oracle whenever the exposer's one
//! sweep ticks. A session that finds itself recalled returns, which drops it and every stream on it. The
//! oracle holds only rules, never a session, so nothing here can list, count, or name the live peers.
//!
//! The unit is the SESSION: a recall ends every stream on it, including streams admitted under other caps,
//! because a dropped stream alone leaves a handler's detached work running.

use core::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use nauthy::{Cap, FileDenylist, Latch, RevocationId, Revocations, VerifyKey};
use tokio::sync::watch;
use tokio::time::{Interval, MissedTickBehavior};

/// How often a live session re-checks the chains it was admitted on. A recall ends the sessions it hits
/// within one sweep plus the store's own refresh debounce, about a second on the serving node; never at
/// the moment it is written. Shorter buys nothing a human would notice and multiplies the per-session
/// checks; longer leaves a recalled peer inside for longer.
///
/// Every sweep runs on the node's one serving task, so its cost is paid by every session and admission
/// on the node. [`MAX_SESSION_CHAIN_IDS`] is what bounds it: at most that many id lookups per session, so
/// a few hundred thousand per sweep across a full session table.
pub(super) const CUT_SWEEP: Duration = Duration::from_secs(1);

/// The most revocation ids one session may keep for the cut. A stream whose admission would take the
/// session past it is refused, the same uniform refusal a gate miss gets.
///
/// The record is a union that lives as long as the session, and it does not dedupe the way a re-presented
/// cap might suggest: anyone holding a cap can attenuate it offline, with no secret, and every attenuation
/// adds a block with a fresh id that still admits. Uncapped, one holder re-narrowing one slip per stream
/// grows one session's record without bound, and every sweep walks it on the serving task. 1,024 is 64
/// distinct caps at full depth, far past any honest session (a client presents one cap per session), and
/// bounds the whole node at 256 sessions of it.
pub(super) const MAX_SESSION_CHAIN_IDS: usize = 1024;

/// The rule a live session is re-checked against: whether the chains it was admitted on are still good.
///
/// Synchronous and cheap, like the gate's own [`Revocations`] store, because every live session asks it on
/// every sweep. It answers about chains only: it never sees a session, a peer, or a count, so no impl can
/// grow into an inventory of who is connected.
///
/// Implemented for nauthy's stores, so a caller shares ONE instance between the gate and the cut and the
/// two can never disagree about a file they each read at a different moment.
pub trait LiveCuts: Send + Sync {
    /// Whether a session admitted on `chains` must end now.
    fn cuts(&self, chains: &AdmittedChains) -> bool;
}

/// Every root key and revocation id of every capability the gate ruled on to admit a session's streams:
/// the facts the cut re-checks, kept instead of the caps themselves.
///
/// A parsed cap is the whole token; the ids and the root are all a revocation or a disabled root ever
/// matches. Held as a union per session: the cut is session-granular, so which stream carried which cap
/// does not matter, and a cap presented again adds nothing.
#[derive(Default)]
pub struct AdmittedChains {
    roots: HashSet<VerifyKey>,
    ids: HashSet<RevocationId>,
}

impl AdmittedChains {
    /// The authority keys the admitted caps are rooted at, as [`Cap::parse`] authenticated them.
    pub fn roots(&self) -> impl Iterator<Item = VerifyKey> + '_ {
        self.roots.iter().copied()
    }

    /// The revocation ids of every block of every admitted cap.
    pub fn ids(&self) -> impl Iterator<Item = &RevocationId> + '_ {
        self.ids.iter()
    }

    /// Keep what the cut will need of `cap`, and nothing else. Test fixtures only: the serving path goes
    /// through [`record_all`](Self::record_all), which enforces the ceiling.
    #[cfg(test)]
    pub(super) fn record(&mut self, cap: &Cap) {
        self.roots.insert(cap.root());
        self.ids.extend(cap.revocation_ids());
    }

    /// Keep what the cut will need of every cap one stream was admitted on, or keep nothing and refuse
    /// when that would take this session past [`MAX_SESSION_CHAIN_IDS`]. All or nothing, so a refused
    /// stream leaves no trace in the record.
    pub(super) fn record_all(&mut self, ruled: &[Cap]) -> Result<(), ChainsFull> {
        let fresh: HashSet<RevocationId> = ruled
            .iter()
            .flat_map(Cap::revocation_ids)
            .filter(|id| !self.ids.contains(id))
            .collect();
        if self.ids.len() + fresh.len() > MAX_SESSION_CHAIN_IDS {
            return Err(ChainsFull);
        }
        self.ids.extend(fresh);
        self.roots.extend(ruled.iter().map(Cap::root));
        Ok(())
    }

    /// How many revocation ids this session keeps.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.ids.len()
    }
}

/// A stream's chains would take its session past [`MAX_SESSION_CHAIN_IDS`].
#[derive(Debug, thiserror::Error)]
#[error("this session already keeps {MAX_SESSION_CHAIN_IDS} revocation ids for the live cut")]
pub(super) struct ChainsFull;

impl LiveCuts for FileDenylist {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        self.is_revoked_any(chains.ids())
    }
}

/// The disabled root first, then the inner store: the same order and the same two questions the gate's
/// own [`Latch`] answers at admission.
impl<R: Revocations + LiveCuts> LiveCuts for Latch<R> {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        chains.roots().any(|root| self.disabled().is_disabled(root)) || self.inner().cuts(chains)
    }
}

/// A shared oracle cuts as the one it shares, which is how the gate and the cut read one instance.
impl<C: LiveCuts + ?Sized> LiveCuts for Arc<C> {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        C::cuts(self, chains)
    }
}

/// The node's half of the cut: the oracle, and the sweep every live session subscribes to.
///
/// Present on the serving context only when a caller wired an oracle, so an exposer without one runs no
/// timer, subscribes no session, and serves exactly as before.
pub(super) struct Cuts {
    oracle: Box<dyn LiveCuts>,
    /// Signals "re-check now". A watch rather than a timer per session: one interval for the node, and a
    /// session that is busy when it fires still sees it on its next turn.
    sweep: watch::Sender<()>,
}

impl Cuts {
    /// Arm the cut over `oracle`.
    pub(super) fn new(oracle: Box<dyn LiveCuts>) -> Self {
        let (sweep, _) = watch::channel(());
        Self { oracle, sweep }
    }

    /// The node's sweep timer. A loop stalled past a tick fires once late rather than in a burst, so a
    /// busy node never re-checks every session several times back to back.
    pub(super) fn interval() -> Interval {
        let mut interval = tokio::time::interval(CUT_SWEEP);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval
    }

    /// Wake every live session to re-check. Cannot fail: with no session subscribed there is simply no
    /// one to wake.
    pub(super) fn sweep(&self) {
        self.sweep.send_replace(());
    }

    /// One session's subscription, and the empty record its streams fill in as they are admitted.
    pub(super) fn watch(&self) -> SessionCut {
        SessionCut {
            sweep: self.sweep.subscribe(),
            chains: Arc::default(),
        }
    }

    /// Whether the session behind `cut` must end now.
    pub(super) fn cuts(&self, cut: &SessionCut) -> bool {
        let chains = cut.chains.lock().unwrap_or_else(PoisonError::into_inner);
        self.oracle.cuts(&chains)
    }
}

/// One session's half of the cut, owned by the session's own frame and dropped with it: nothing outside
/// the session can reach it, so a session that ends by any path leaves nothing behind to clean up.
pub(super) struct SessionCut {
    sweep: watch::Receiver<()>,
    /// Filled by the session's streams as each is admitted, read by the session's loop on a sweep. A
    /// `std` mutex held for one insert or one oracle call and never across an await.
    chains: Arc<Mutex<AdmittedChains>>,
}

impl SessionCut {
    /// The record this session's streams write their admitted chains into.
    pub(super) fn chains(&self) -> Arc<Mutex<AdmittedChains>> {
        Arc::clone(&self.chains)
    }

    /// Resolve on the next sweep, `true`; or `false` once the node's sweep is gone for good, which only
    /// happens as the node itself stops.
    pub(super) async fn swept(&mut self) -> bool {
        self.sweep.changed().await.is_ok()
    }
}

/// Resolve on the next sweep of a wired cut; never for a session with none, so its arm stays inert.
pub(super) async fn swept(cut: &mut Option<SessionCut>) -> bool {
    match cut {
        Some(cut) => cut.swept().await,
        None => core::future::pending().await,
    }
}

/// Resolve on the next tick of a wired sweep; never for a node with none.
pub(super) async fn tick(interval: &mut Option<Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => core::future::pending().await,
    }
}

#[cfg(test)]
#[path = "cut_tests.rs"]
mod cut_tests;
