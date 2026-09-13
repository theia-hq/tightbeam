//! The open-safety markers: the const each carries, and the seal that closes the family.
//!
//! The negative case (a third downstream marker is rejected by the seal) is a `compile_fail` doc-test on the
//! module, since a rejection cannot be asserted from inside a build that must still compile.

use crate::open_policy::{Never, OptIn, PublicUse};

/// The whole payload of each marker, checked at compile time: a `Never` handler is never open-safe, an
/// `OptIn` handler may be. An assembler reads exactly this const to refuse an open gate over a `Never`.
const _: () = {
    assert!(!<Never as PublicUse>::OPEN_SAFE);
    assert!(<OptIn as PublicUse>::OPEN_SAFE);
};

/// A generic reader projects `OPEN_SAFE` through the trait bound, the shape a later assembler uses to read
/// the marker off a handler's associated type. This is the const monomorphized per marker, not a runtime read.
fn open_safe<P: PublicUse>() -> bool {
    P::OPEN_SAFE
}

#[test]
fn never_is_not_open_safe_and_optin_is() {
    assert!(!open_safe::<Never>());
    assert!(open_safe::<OptIn>());
}
