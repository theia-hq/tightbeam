//! The live cut: a session admitted on a capability that is later recalled, or on a grant that has since
//! run out, ends itself, rather than running on until its peer leaves.
//!
//! Admission rules per stream, at the moment the stream opens, so a recall written after that moment has
//! no stream left to refuse. The cut closes that gap without a registry of who is connected: each session
//! keeps the chains it was admitted on, in its own frame, and re-asks the oracle whenever the exposer's one
//! sweep ticks. A session that finds itself recalled or expired, anchored at a root no longer trusted, or
//! held by a peer whose key is revoked returns, which drops it and every stream on it. The oracle holds only rules, never a session, so nothing here can list, count, or name the live
//! peers.
//!
//! The unit is the SESSION: a recall or an expiry ends every stream on it, including streams admitted
//! under other caps, because a dropped stream alone leaves a handler's detached work running.

use core::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use nauthy::{Cap, CapError, FileDenylist, Latch, RevocationId, Revocations, VerifyKey};
use tokio::sync::watch;
use tokio::time::{Interval, MissedTickBehavior};

/// How often a live session re-checks the chains it was admitted on. A recall ends the sessions it hits
/// within one sweep plus the store's own refresh debounce, about a second on the serving node; never at
/// the moment it is written. An expiry ends its session within one sweep of the instant it passes.
/// Shorter buys nothing a human would notice and multiplies the per-session checks; longer leaves a
/// recalled peer inside for longer.
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
/// every sweep. It answers about one session's record at a time: it never sees a session or a count, so no
/// impl can grow into an inventory of who is connected.
///
/// Implemented for nauthy's stores, so a caller shares ONE instance between the gate and the cut and the
/// two can never disagree about a file they each read at a different moment.
///
/// A wrapper that holds an oracle must forward [`trusts`](Self::trusts) and
/// [`revoked_peer`](Self::revoked_peer) as well as [`cuts`](Self::cuts): a provided method a wrapper does
/// not write answers the default, not the inner oracle, and would trust every anchor and every peer.
pub trait LiveCuts: Send + Sync {
    /// Whether a session admitted on `chains` must end now.
    fn cuts(&self, chains: &AdmittedChains) -> bool;

    /// Whether a session anchored at `anchor` may keep running: the root the gate verified a stream's
    /// first cap under, which a gate whose trusted root can change may since have stopped trusting. A
    /// session ends when ANY of its anchors is no longer trusted, so a session that mixed streams under an
    /// old root and a still-trusted one does not ride the second past the change.
    ///
    /// Provided, trusting every anchor: an oracle behind a gate whose root never changes keeps the default.
    fn trusts(&self, _anchor: &VerifyKey) -> bool {
        true
    }

    /// Whether the key of the peer a session proved is revoked, which ends the session whatever caps it
    /// was admitted on. The gate refuses a revoked peer at admission; this reaches a session admitted
    /// before the revocation.
    ///
    /// Provided, revoking no key: an oracle over a store that keeps no keys keeps the default.
    fn revoked_peer(&self, _peer: &VerifyKey) -> bool {
        false
    }
}

/// Every root key and revocation id of every capability the gate ruled on to admit a session's streams,
/// the anchors those streams were verified under, the peer key they were bound to, and how long those
/// grants hold the session: the facts the cut re-checks, kept instead of the caps themselves.
///
/// A parsed cap is the whole token; the ids and the root are all a revocation or a disabled root ever
/// matches. Held as a union per session: the cut is session-granular, so which stream carried which cap
/// does not matter, and a cap presented again adds nothing.
#[derive(Default)]
pub struct AdmittedChains {
    roots: HashSet<VerifyKey>,
    ids: HashSet<RevocationId>,
    anchors: HashSet<VerifyKey>,
    peer: Option<VerifyKey>,
    lease: Lease,
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

    /// The root of each admitted stream's first cap: the one the gate verified at its own authority, so
    /// the root the session's standing hangs on. A badge presented second, on the two-token path, is never
    /// an anchor: it is rooted at the authority its slip names, which no change to the gate's trusted root
    /// moves, and it stays in [`roots`](Self::roots), where a disabled root still cuts it.
    pub fn anchors(&self) -> impl Iterator<Item = VerifyKey> + '_ {
        self.anchors.iter().copied()
    }

    /// The key the session's peer proved, once any of its streams was admitted on a cap. `None` for a
    /// session whose every stream took the open path, where the key was announced and ruled on by nothing.
    pub fn peer(&self) -> Option<VerifyKey> {
        self.peer
    }

    /// Keep what the cut will need of `cap`, and nothing else. Test fixtures only: the serving path goes
    /// through [`record_all`](Self::record_all), which enforces the ceiling.
    #[cfg(test)]
    pub(super) fn record(&mut self, cap: &Cap) {
        self.roots.insert(cap.root());
        self.anchors.insert(cap.root());
        self.ids.extend(cap.revocation_ids());
        let until =
            Lease::of_stream(core::slice::from_ref(cap)).expect("a fixture cap's expiry reads");
        self.lease = self.lease.extend(until);
    }

    /// Whether any grant this session was admitted on has run out by `now`. Never for a session no
    /// stream was admitted on a grant, and never for one whose every grant never expires.
    pub(super) fn lapsed(&self, now: SystemTime) -> bool {
        self.lease.lapsed(now)
    }

    /// Keep what the cut will need of every cap one stream was admitted on, and of the `peer` it was bound
    /// to, or keep nothing and refuse the stream: when a cap's expiry cannot be read, or when keeping it
    /// would take this session past [`MAX_SESSION_CHAIN_IDS`]. All or nothing, so a refused stream leaves
    /// no trace in the record.
    ///
    /// `ruled` lists the cap the gate verified at its own authority first, so its root is the stream's
    /// anchor, and a badge after it is not.
    pub(super) fn record_all(&mut self, peer: VerifyKey, ruled: &[Cap]) -> Result<(), Unrecorded> {
        // Fail closed: a grant whose end cannot be read is treated as already over, so the stream it
        // would admit is refused here rather than served on a lease nobody can bound.
        let until = Lease::of_stream(ruled).map_err(Unrecorded::UnreadableExpiry)?;
        let fresh: HashSet<RevocationId> = ruled
            .iter()
            .flat_map(Cap::revocation_ids)
            .filter(|id| !self.ids.contains(id))
            .collect();
        if self.ids.len() + fresh.len() > MAX_SESSION_CHAIN_IDS {
            return Err(Unrecorded::Full);
        }
        self.ids.extend(fresh);
        self.roots.extend(ruled.iter().map(Cap::root));
        // An open stream rules on nothing, so it has no grant to bound the session by, no anchor, and no
        // proven peer.
        if let Some(anchor) = ruled.first() {
            self.anchors.insert(anchor.root());
            self.peer = Some(peer);
            self.lease = self.lease.extend(until);
        }
        Ok(())
    }

    /// How many revocation ids this session keeps.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.ids.len()
    }
}

/// How long a session's grants hold it open: until the FIRST of its streams' grants runs out.
///
/// One stream is admitted only while every cap it was ruled on holds (the foreign path ANDs a slip and a
/// badge), so a stream's grant runs out at the EARLIEST of their expiries. The session ends at the
/// EARLIEST of those too, the rule a recall already follows: any one grant ending ends the session, the
/// same as any one chain recalled. Were it the latest, a stream on a short grant would ride any later
/// grant from the same root, even one for another service, past its own expiry. The cost falls only on
/// a client that puts several grants on one session, which loses them all at the first expiry and
/// reconnects; a client presents one cap per session, so it pays nothing. Each cap's expiry is
/// [`Cap::valid_until`], the earliest bound anywhere in its chain, so a holder who narrowed a grant and
/// passed it on is cut at the narrower instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Lease {
    /// No stream was admitted on a grant: nothing here can run out.
    #[default]
    Unruled,
    /// Some grant a stream was admitted on has run out once this instant passes.
    Until(SystemTime),
    /// Every stream was admitted on grants none of which ever expires, so time alone never ends this
    /// session. A recall still does.
    Unbounded,
}

impl Lease {
    /// The expiry of one stream's grant, from the caps it was ruled on.
    fn of_stream(ruled: &[Cap]) -> Result<Option<SystemTime>, CapError> {
        Self::earliest(ruled.iter().map(Cap::valid_until))
    }

    /// The earliest of one stream's expiry reads: `None` when no cap ever expires, and an error when any
    /// read failed, because an unreadable expiry is treated as expired and never as absent.
    fn earliest(
        reads: impl IntoIterator<Item = Result<Option<SystemTime>, CapError>>,
    ) -> Result<Option<SystemTime>, CapError> {
        reads
            .into_iter()
            .try_fold(None, |earliest: Option<SystemTime>, read| {
                Ok(match (earliest, read?) {
                    (Some(held), Some(until)) => Some(held.min(until)),
                    (held, until) => held.or(until),
                })
            })
    }

    /// This lease with one more admitted stream, whose grant runs out at `stream`. It can only ever
    /// shorten: a grant that never expires leaves a bounded lease as it was.
    fn extend(self, stream: Option<SystemTime>) -> Self {
        match (self, stream) {
            (Self::Unruled | Self::Unbounded, None) => Self::Unbounded,
            (Self::Unruled | Self::Unbounded, Some(until)) => Self::Until(until),
            (Self::Until(held), Some(until)) => Self::Until(held.min(until)),
            (held @ Self::Until(_), None) => held,
        }
    }

    /// Whether the lease has run out at `now`. A cap is good through its expiry instant (the gate checks
    /// `time <= expiry`), so it lapses only strictly after.
    fn lapsed(self, now: SystemTime) -> bool {
        matches!(self, Self::Until(until) if now > until)
    }
}

/// Why the cut ended a session, for the node's own log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cut {
    /// A cap it was admitted on is revoked, or the root one was issued under is disabled.
    Recalled,
    /// A root one of its streams was verified under is no longer trusted.
    Untrusted,
    /// The key its peer proved is revoked.
    PeerRevoked,
    /// A grant it was admitted on has expired.
    Expired,
}

impl core::fmt::Display for Cut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Recalled => "a capability it was admitted on is revoked or its root disabled",
            Self::Untrusted => "a root it was admitted under is no longer trusted",
            Self::PeerRevoked => "its peer's key is revoked",
            Self::Expired => "a capability it was admitted on has expired",
        })
    }
}

/// Why a stream's chains were not kept, which refuses the stream.
#[derive(Debug, thiserror::Error)]
pub(super) enum Unrecorded {
    /// They would take the session past [`MAX_SESSION_CHAIN_IDS`].
    #[error("this session already keeps {MAX_SESSION_CHAIN_IDS} revocation ids for the live cut")]
    Full,
    /// A cap's expiry cannot be read, so it is treated as already expired.
    #[error("a capability's expiry cannot be read, so the live cut treats it as expired")]
    UnreadableExpiry(#[source] CapError),
}

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

/// A shared oracle answers as the one it shares, which is how the gate and the cut read one instance.
impl<C: LiveCuts + ?Sized> LiveCuts for Arc<C> {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        C::cuts(self, chains)
    }

    fn trusts(&self, anchor: &VerifyKey) -> bool {
        C::trusts(self, anchor)
    }

    fn revoked_peer(&self, peer: &VerifyKey) -> bool {
        C::revoked_peer(self, peer)
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

    /// Whether the session behind `cut` must end at `now`, and why. Expiry is checked here, beside the
    /// oracle rather than inside it, so every oracle a caller wires gets it and none can forget it. So is
    /// the walk over the session's anchors and its peer: the oracle only rules on one key at a time.
    pub(super) fn cuts(&self, cut: &SessionCut, now: SystemTime) -> Option<Cut> {
        let chains = cut.chains.lock().unwrap_or_else(PoisonError::into_inner);
        if self.oracle.cuts(&chains) {
            return Some(Cut::Recalled);
        }
        if chains.anchors().any(|anchor| !self.oracle.trusts(&anchor)) {
            return Some(Cut::Untrusted);
        }
        if chains
            .peer()
            .is_some_and(|peer| self.oracle.revoked_peer(&peer))
        {
            return Some(Cut::PeerRevoked);
        }
        chains.lapsed(now).then_some(Cut::Expired)
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
