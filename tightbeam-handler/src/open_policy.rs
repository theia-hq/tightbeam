//! The open-safety marker family a [`Handler`](crate::Handler) declares: does this service have a
//! legitimate PUBLIC use, or must it never face an unauthenticated stranger?
//!
//! A handler names one of three markers as an associated type, so the answer is a COMPILE-TIME property of
//! the handler, with no forgettable default. The marker names the LEGITIMACY question ("is there any
//! legitimate public use"), never the auth mechanism: [`Never`] = a keyless shell no operator may serve
//! to strangers, [`OptIn`] = legitimate to serve publicly IF the operator opts in, [`ProvenOnly`] = built
//! for a peer whose key the transport proved and who holds no standing here. It carries its public
//! payload as [`PublicUse::OPEN_SAFE`], a const the type carries: readable by any consumer, implementable
//! only by the three sealed markers here. An assembler reads it once at construction to refuse an open gate
//! over a [`Never`] or [`ProvenOnly`] handler.
//!
//! Each marker also fixes which witness origins its handler accepts, and the three sets are disjoint where
//! it matters: [`Never`] accepts [`Rooted`](nauthy::Origin::Rooted) only, [`OptIn`] accepts `Rooted` and
//! [`Open`](nauthy::Origin::Open), and [`ProvenOnly`] accepts [`Proven`](nauthy::Origin::Proven) only. So a
//! proven key with no standing never reaches a handler that trusts its peer or one that serves strangers.
//!
//! The marker is SEALED (a private supertrait): only the three markers here implement it, so a downstream
//! crate cannot add a fourth, more-permissive variant. The markers are UNINHABITED (`enum Never {}`), so no
//! value can be forged and named where a marker type is expected. Both properties make "a keyless service
//! mislabeled open" a compile error, not a runtime hope.
//!
//! [`Handler`](crate::Handler) names one of these markers as its `type Exposure: PublicUse`, and the proof is
//! prepared on the serve path: a handler refuses a witness its marker does not accept before any success
//! response (see [`Served`](crate::Served)).
//!
//! The seal is necessary, so it is guarded by a compile-fail probe: a downstream marker is REJECTED because
//! the `sealed::Sealed` supertrait it would need is private and unnameable. This doc-test fails to build (as
//! it must) precisely because a fourth marker cannot satisfy `PublicUse`:
//!
//! ```compile_fail
//! use tightbeam_handler::open_policy::PublicUse;
//! enum AlsoPublic {}
//! // No way to `impl sealed::Sealed for AlsoPublic` (the module is private), so this cannot compile:
//! impl PublicUse for AlsoPublic {
//!     const OPEN_SAFE: bool = true;
//! }
//! ```

use nauthy::Origin;

/// Does this handler have a legitimate PUBLIC use: may it EVER face an unauthenticated stranger, if the
/// operator opts in?
///
/// A per-service property the handler author declares as an associated type, with no default (the author
/// MUST name one of [`Never`] / [`OptIn`] / [`ProvenOnly`]). It is the CEILING, not the choice: it says
/// whether public is *ever* legitimate, never that this exposure IS public (the operator still opts in at run
/// time). Sealed to the three markers in this module; a downstream crate cannot add a fourth.
///
/// If in doubt, or if your handler does no auth of its own, pick [`Never`]: the gate then authenticates for
/// you, and the worst case is a service that is gated when it could have been public, never a keyless service
/// served open by accident.
pub trait PublicUse: sealed::Sealed + Send + Sync + 'static {
    /// Whether serving this handler to an unauthenticated stranger is ever legitimate: `Never = false`,
    /// `OptIn = true`, `ProvenOnly = false`. The type carries the answer, never a bool a caller passes; the
    /// const is readable by any consumer, but only the three sealed markers can implement it. An assembler
    /// reads it once at construction to refuse an open gate over a [`Never`] or [`ProvenOnly`] handler.
    const OPEN_SAFE: bool;
}

/// No legitimate public use: this service must NEVER be served to strangers.
///
/// A shell handler handed to an unauthenticated peer is a keyless remote-code-execution shell; there is no
/// operator opt-in that makes that safe, so the marker forbids it at compile time rather than trusting a
/// runtime flag. This is the fail-closed choice: if in doubt, or if your handler does no auth of its own,
/// pick `Never` and let the gate authenticate for you.
///
/// Uninhabited (`enum Never {}`): it names a policy, never a value, so no one can forge a `Never` and slip it
/// where a permissive marker was meant.
pub enum Never {}

/// A legitimate public use: MAY be served to strangers IF the operator opts in.
///
/// A public download (an HTTP fetch), a public speedtest (a throughput responder): serving these to an
/// anonymous stranger is a use an operator could legitimately stand behind, so the marker PERMITS the
/// operator to open them. It only permits; it never makes the exposure public by itself (the operator still
/// opts in at run time, and an open serve may carry its own caveats, e.g. an uncapped fetch is an egress
/// relay). Pick this only if serving your handler to an anonymous stranger is a use you would deliberately
/// stand behind.
///
/// Uninhabited (`enum OptIn {}`): like [`Never`], it names a policy, never a value.
pub enum OptIn {}

/// Built for a peer whose key the transport proved and who presented no token: it answers that key and
/// grants it nothing.
///
/// Such a handler accepts a [`Proven`](nauthy::Origin::Proven) witness and nothing else, and no other
/// marker accepts `Proven`. A `Proven` witness carries no authority, so a handler that trusts its peer
/// ([`Never`]) must never see one; and a handler that serves strangers ([`OptIn`]) would serve the proven
/// key everything it serves an anonymous peer, so it must not see one either. It is not open-safe: a
/// stranger who proves nothing never reaches it.
///
/// Uninhabited (`enum ProvenOnly {}`): like [`Never`], it names a policy, never a value.
pub enum ProvenOnly {}

impl PublicUse for Never {
    const OPEN_SAFE: bool = false;
}

impl PublicUse for OptIn {
    const OPEN_SAFE: bool = true;
}

impl PublicUse for ProvenOnly {
    const OPEN_SAFE: bool = false;
}

/// Each match is exhaustive, with no wildcard, so a new origin must be ruled on for every marker.
impl sealed::Sealed for Never {
    fn accepts(origin: Origin) -> bool {
        match origin {
            Origin::Rooted => true,
            Origin::Open | Origin::Proven => false,
        }
    }
}

impl sealed::Sealed for OptIn {
    fn accepts(origin: Origin) -> bool {
        match origin {
            Origin::Rooted | Origin::Open => true,
            Origin::Proven => false,
        }
    }
}

impl sealed::Sealed for ProvenOnly {
    fn accepts(origin: Origin) -> bool {
        match origin {
            Origin::Proven => true,
            Origin::Rooted | Origin::Open => false,
        }
    }
}

/// Whether a handler whose marker is `P` accepts a witness of `origin`: the rule
/// [`Served`](crate::Served)'s mint applies. Crate-private, so the rule stays inside the seal.
pub(crate) fn accepts<P: PublicUse>(origin: Origin) -> bool {
    <P as sealed::Sealed>::accepts(origin)
}

/// The one-way conversion relation between exposure ceilings, read by
/// [`Served::delegate`](crate::Served::delegate) as a method bound: an outer handler may hand its proof
/// inward only to an inner whose ceiling is compatible with its own.
///
/// The impls say exactly:
/// - [`Never`] is compatible with itself and [`OptIn`] (a `Never` outer only ever holds a rooted witness,
///   which either may accept),
/// - [`OptIn`] is compatible only with [`OptIn`] (an open witness may reach an open-permitting inner, never
///   a [`Never`] one), and
/// - [`ProvenOnly`] is compatible only with [`ProvenOnly`], in both directions: a proven witness reaches
///   no other marker, and no other marker's witness reaches a `ProvenOnly` inner.
///
/// There is deliberately NO `Compatible<Never> for OptIn`, and no edge between [`ProvenOnly`] and any other
/// marker: the laundering case is not a runtime refusal, it is a compile error at the wrapper's `delegate`
/// call, so a lying `OptIn` wrapper cannot even name a `Never` inner. The relation is sealed the same way [`PublicUse`] is, so a downstream crate cannot add the missing
/// laundering impl. The reflexive-and-widening pair (rather than a blanket `impl<Inner: PublicUse>
/// Compatible<Inner> for Never` beside the reflexive impl) is coherence-clean: the blanket overlaps the
/// reflexive impl at `Compatible<Never> for Never` (E0119), while `impl Compatible<OptIn> for Never` does
/// not.
pub trait Compatible<Inner: PublicUse>: PublicUse {}

impl<T: PublicUse> Compatible<T> for T {}
impl Compatible<OptIn> for Never {}

/// Seals [`PublicUse`]: a downstream crate cannot name `sealed::Sealed` (the module is private), so it cannot
/// implement `PublicUse` for a type of its own. The marker set is closed to the three in this module, which
/// is what makes "no fourth, more-permissive marker" a compile-time guarantee rather than a convention. The
/// origin rule lives here too, so no one outside this crate can read or restate it.
mod sealed {
    use nauthy::Origin;

    pub trait Sealed {
        /// Whether a handler with this marker accepts a witness of `origin`.
        fn accepts(origin: Origin) -> bool;
    }
}
