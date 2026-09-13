//! The serving-proof wall: the mint refuses an open witness for a `Never` handler, delegation preserves
//! the witness and re-applies the target ceiling, and `into_rooted` is the one narrowing seam.
//!
//! The mint is crate-private, so these proofs are only reachable from inside this crate: an outside crate
//! consumes a proof through the erased bridge, pinned by the compile-fail doc tests on [`Served`].

use core::time::Duration;

use nauthy::{Gate, ProvenPeer, Service};

use crate::contract::{RootedAdmitted, ServeError, Served};
use crate::open_policy::{Never, OptIn};
use crate::{BoxRead, BoxWrite, Handler};

/// A do-nothing GATED handler (`type Exposure = Never`): a handler with no public use of its own, so an open
/// witness must not mint its proof.
struct GatedNoop;

impl Handler for GatedNoop {
    type Exposure = Never;

    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// A do-nothing OPEN handler (`type Exposure = OptIn`): a legitimately-public responder, which an open
/// witness may reach.
struct OpenNoop;

impl Handler for OpenNoop {
    type Exposure = OptIn;

    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// Mint an [`Admitted`](nauthy::Admitted) witness through the only public mint (the gate), for the proof
/// tests below. `rooted` picks a rooted gate with a member badge vs an open gate.
fn witness(rooted: bool) -> nauthy::Admitted {
    let signet = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
    let peer = nauthy::Identity::from_secret(&[9u8; 32])
        .expect("valid secret")
        .verifying_key();
    let service: Service = "locked".parse().expect("valid service name");
    if rooted {
        let badge = signet
            .mint_member(peer, nauthy::Request::expires_in(Duration::from_secs(300)))
            .expect("mint a member badge");
        let gate = Gate::rooted(
            signet.verifying_key(),
            nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-handler-witness-rooted")),
        );
        gate.admit_witnessed(ProvenPeer::from_handshake(peer), Some(&badge), &service)
            .expect("a member badge admits")
    } else {
        Gate::Open
            .admit_witnessed(ProvenPeer::from_handshake(peer), None, &service)
            .expect("an open gate admits anyone")
    }
}

/// The proof mint wall, in both directions: a rooted witness mints a `Never` handler's proof, an open
/// witness does not (fail-closed); an open witness still mints an `OptIn` handler's proof.
#[test]
fn a_rooted_witness_mints_a_never_proof_and_an_open_one_does_not() {
    assert!(
        Served::<GatedNoop>::mint(witness(true)).is_ok(),
        "a rooted witness mints a Never handler's proof"
    );
    assert!(
        Served::<GatedNoop>::mint(witness(false)).is_err(),
        "an open witness cannot mint a Never handler's proof (fail-closed)"
    );
    assert!(
        Served::<OpenNoop>::mint(witness(false)).is_ok(),
        "an open witness mints an OptIn handler's proof"
    );
}

/// Delegation preserves the witness and re-applies the target ceiling: a rooted `Never` proof delegates
/// both to another `Never` inner (reflexive) and to an `OptIn` inner (widening); an open `OptIn` proof
/// delegates only to an `OptIn` inner. The `OptIn -> Never` widening is a compile error, pinned by the
/// `Served` doc test.
#[test]
fn delegation_preserves_the_witness_and_the_ceiling() {
    let rooted = Served::<GatedNoop>::mint(witness(true)).expect("rooted mints");
    assert!(
        rooted.delegate::<GatedNoop>().is_ok(),
        "a rooted Never proof delegates to a Never inner (reflexive)"
    );
    let rooted = Served::<GatedNoop>::mint(witness(true)).expect("rooted mints");
    assert!(
        rooted.delegate::<OpenNoop>().is_ok(),
        "a rooted Never proof delegates to an OptIn inner (widening)"
    );
    let open = Served::<OpenNoop>::mint(witness(false)).expect("open mints");
    assert!(
        open.delegate::<OpenNoop>().is_ok(),
        "an open OptIn proof delegates to an OptIn inner"
    );
}

/// The engine seam: `into_rooted` narrows a rooted proof to a [`RootedAdmitted`] and refuses an open one
/// with [`ServeError::OpenAdmission`], so a keyless engine that demands the token cannot be reached with
/// an open witness.
#[test]
fn into_rooted_narrows_a_rooted_proof_and_refuses_an_open_one() {
    let peer = nauthy::Identity::from_secret(&[9u8; 32])
        .expect("valid secret")
        .verifying_key();
    let rooted: RootedAdmitted = Served::<GatedNoop>::mint(witness(true))
        .expect("rooted mints")
        .into_rooted()
        .expect("a rooted witness narrows");
    assert_eq!(rooted.peer(), peer);
    let open = Served::<OpenNoop>::mint(witness(false))
        .expect("open mints")
        .into_rooted();
    assert!(
        matches!(open, Err(ServeError::OpenAdmission)),
        "an open witness cannot narrow to a rooted token"
    );
    // The transitional conversion hands the rooted witness on to an engine that still takes the untyped
    // `Admitted`; only a rooted proof can produce one.
    let admitted = Served::<GatedNoop>::mint(witness(true))
        .expect("rooted mints")
        .into_rooted()
        .expect("a rooted witness narrows")
        .into_admitted();
    assert_eq!(
        admitted.peer(),
        peer,
        "the transitional conversion preserves the admitted peer"
    );
}
