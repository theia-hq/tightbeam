//! The open-safety markers: the const each carries, and the seal that closes the family.
//!
//! The negative case (a third downstream marker is rejected by the seal) is a `compile_fail` doc-test on the
//! module, since a rejection cannot be asserted from inside a build that must still compile.

use core::marker::PhantomData;

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

/// The ratified supertraits (`PublicUse: Send + Sync + 'static`, delib-56 verdict 2): a generic wrapper can
/// hold the marker in `PhantomData` knowing only the `PublicUse` bound. This generic body fails E0277
/// without the supertraits, which is the downstream wrapper shape the clause exists for.
#[test]
fn a_public_use_marker_rides_in_a_send_wrapper() {
    fn ride<P: PublicUse>() {
        struct Wrapper<P: PublicUse>(PhantomData<P>);
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Wrapper<P>>();
    }
    ride::<Never>();
    ride::<OptIn>();
}
