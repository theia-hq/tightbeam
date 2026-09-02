//! The open-safety marker family a [`Handler`](crate::tunnel::Handler) declares: does this service have a
//! legitimate PUBLIC use, or must it never face an unauthenticated stranger?
//!
//! A handler names one of two markers as an associated type, so the answer is a COMPILE-TIME property of the
//! handler, with no forgettable default. The marker names the LEGITIMACY question (delib-37's S6 predicate:
//! "no legitimate public USE"), never the auth mechanism: [`Never`] = a keyless shell no operator may serve
//! to strangers, [`OptIn`] = legitimate to serve publicly IF the operator opts in. It carries its whole
//! payload as [`PublicUse::OPEN_SAFE`], a private const an assembler reads once at construction to refuse an
//! open gate over a [`Never`] handler.
//!
//! The marker is SEALED (a private supertrait): only the two markers here implement it, so a downstream
//! crate cannot add a third, more-permissive variant. The markers are UNINHABITED (`enum Never {}`), so no
//! value can be forged and named where a marker type is expected. Both properties make "a keyless service
//! mislabeled open" a compile error, not a runtime hope.
//!
//! This is a dead-code scaffold this increment: [`Handler`](crate::tunnel::Handler) gains its
//! `type Public: PublicUse` in a later increment, and the assembler's open-gate refusal is wired then.
//!
//! The seal is load-bearing, so it is guarded by a compile-fail probe: a downstream marker is REJECTED
//! because the `sealed::Sealed` supertrait it would need is private and unnameable. This doc-test fails to
//! build (as it must) precisely because the third marker cannot satisfy `PublicUse`:
//!
//! ```compile_fail
//! use tightbeam::open_policy::PublicUse;
//! enum AlsoPublic {}
//! // No way to `impl sealed::Sealed for AlsoPublic` (the module is private), so this cannot compile:
//! impl PublicUse for AlsoPublic {
//!     const OPEN_SAFE: bool = true;
//! }
//! ```

/// Does this handler have a legitimate PUBLIC use: may it EVER face an unauthenticated stranger, if the
/// operator opts in?
///
/// A per-service property the handler author declares as an associated type, with no default (the author
/// MUST name one of [`Never`] / [`OptIn`]). It is the CEILING, not the choice: it says whether public is
/// *ever* legitimate, never that this exposure IS public (the operator still opts in at run time). Sealed to
/// the two markers in this module; a downstream crate cannot add a third.
///
/// If in doubt, or if your handler does no auth of its own, pick [`Never`]: the gate then authenticates for
/// you, and the worst case is a service that is gated when it could have been public, never a keyless service
/// served open by accident.
pub trait PublicUse: sealed::Sealed {
    /// Whether serving this handler to an unauthenticated stranger is ever legitimate: `Never = false`,
    /// `OptIn = true`. Private (the whole point of the marker is that the answer is the TYPE, not a bool a
    /// caller passes); an assembler reads it once at construction to refuse an open gate over a `Never`
    /// handler.
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
/// A public download (`fetch`), a public speedtest (`ping`/`speed`): serving these to an anonymous stranger
/// is a use an operator could legitimately stand behind, so the marker PERMITS the operator to open them. It
/// only permits; it never makes the exposure public by itself (the operator still opts in at run time, and an
/// open serve may carry its own caveats, e.g. an uncapped `fetch` is an egress relay). Pick this only if
/// serving your handler to an anonymous stranger is a use you would deliberately stand behind.
///
/// Uninhabited (`enum OptIn {}`): like [`Never`], it names a policy, never a value.
pub enum OptIn {}

impl PublicUse for Never {
    const OPEN_SAFE: bool = false;
}

impl PublicUse for OptIn {
    const OPEN_SAFE: bool = true;
}

impl sealed::Sealed for Never {}
impl sealed::Sealed for OptIn {}

/// Seals [`PublicUse`]: a downstream crate cannot name `sealed::Sealed` (the module is private), so it cannot
/// implement `PublicUse` for a type of its own. The marker set is closed to the two in this module, which is
/// what makes "no third, more-permissive marker" a compile-time guarantee rather than a convention.
mod sealed {
    pub trait Sealed {}
}
