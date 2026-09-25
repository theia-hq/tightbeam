//! The serving-proof wall: the mint refuses an open witness for a `Never` handler and a proven witness for
//! every handler but a `ProvenOnly` one, which accepts nothing else; delegation preserves the witness and
//! re-applies the target ceiling, `into_rooted` is the one narrowing seam, and the erased bridge refuses at
//! `prepare` before any success and serves only through the prepared step.
//!
//! The mint is crate-private, so these proofs are only reachable from inside this crate: an outside crate
//! consumes a proof through the erased bridge, pinned by the compile-fail doc tests on [`Served`].

use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Waker};
use core::time::Duration;
use std::sync::Arc;

use bifrost_core::Refusal;
use nauthy::{Gate, Origin, ProvenPeer, Service};
use tokio::io::{empty, sink};

use crate::bridge::ErasedHandler as _;
use crate::contract::{RootedAdmitted, ServeError, Served};
use crate::open_policy::{Never, OptIn, ProvenOnly};
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

/// A do-nothing PROVEN handler (`type Exposure = ProvenOnly`): it answers a transport-proven key with no
/// standing, so a proven witness is the only one that mints its proof.
struct ProvenNoop;

impl Handler for ProvenNoop {
    type Exposure = ProvenOnly;

    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// An OPEN handler that records that it ran: the bridge's prepared serve step must actually drive the
/// handler body, not just mint a type-level token.
struct ObservedNoop(Arc<AtomicBool>);

impl Handler for ObservedNoop {
    type Exposure = OptIn;

    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        self.0.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// Mint an [`Admitted`](nauthy::Admitted) witness through the only public mint (the gate), for the proof
/// tests below. `rooted` picks a rooted gate with a member badge vs an open gate.
fn witness(rooted: bool) -> nauthy::Admitted {
    let root = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
    let peer = nauthy::Identity::from_secret(&[9u8; 32])
        .expect("valid secret")
        .verifying_key();
    let service: Service = "locked".parse().expect("valid service name");
    if rooted {
        let badge = root
            .mint_member(peer, nauthy::Request::expires_in(Duration::from_secs(300)))
            .expect("mint a member badge");
        let gate = Gate::rooted(
            root.verifying_key(),
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

/// A [`Proven`](Origin::Proven) witness, minted the only way one is: the gate witnessing a transport-proven
/// key that presented no token.
fn proven_witness() -> nauthy::Admitted {
    let root = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
    let peer = nauthy::Identity::from_secret(&[9u8; 32])
        .expect("valid secret")
        .verifying_key();
    let gate = Gate::rooted(
        root.verifying_key(),
        nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-handler-witness-proven")),
    );
    let witness = gate
        .proven(ProvenPeer::from_handshake(peer))
        .expect("an unrevoked proven key is witnessed");
    assert_eq!(witness.origin(), Origin::Proven);
    witness
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

/// The erased bridge's `prepare`, the dispatcher's pre-success seam: an open witness is refused for a
/// `Never` handler before any success can exist (no `Prepared` is minted), a rooted witness mints, and an
/// open witness mints an `OptIn` handler's proof. The wire-level ordering (no `Response::Ok` before this
/// call returns `Ok`) is pinned in tightbeam's `serve_request` test.
#[test]
fn the_bridge_refuses_an_open_witness_for_never_before_minting() {
    let gated = GatedNoop;
    assert!(
        matches!(gated.prepare(witness(false)), Err(Refusal::NotAdmitted)),
        "an open witness is refused before any success"
    );
    assert!(
        gated.prepare(witness(true)).is_ok(),
        "a rooted witness mints a Never proof"
    );
    assert!(
        OpenNoop.prepare(witness(false)).is_ok(),
        "an open witness mints an OptIn proof"
    );
}

/// `Prepared::serve` runs the frozen handler for the one stream: the bridge's proof drives the handler body.
#[test]
fn prepared_serve_runs_the_frozen_handler() {
    let ran = Arc::new(AtomicBool::new(false));
    let handler = ObservedNoop(Arc::clone(&ran));
    let prepared = handler
        .prepare(witness(false))
        .expect("an open witness mints an OptIn proof");
    // The no-op handler has no await before its body, so one poll with a no-op waker runs it to completion;
    // the contract stays runtime-free.
    let mut serve = Box::pin(prepared.serve(Box::new(sink()), Box::new(empty())));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    assert!(
        serve.as_mut().poll(&mut context).is_ready(),
        "the no-op handler's serve completes in one poll"
    );
    assert!(
        ran.load(Ordering::SeqCst),
        "Prepared::serve ran the handler body"
    );
}

/// Delegation preserves the witness and re-applies the target ceiling: a rooted `Never` proof delegates
/// both to another `Never` inner (reflexive) and to an `OptIn` inner (widening); an open `OptIn` proof
/// delegates only to an `OptIn` inner. The `OptIn -> Never` laundering delegation is a compile error, pinned
/// by the `Served` doc test.
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

/// A proven witness mints no `Never` or `OptIn` proof. It carries no authority, so a `Never` handler (one
/// that trusts its peer, a keyless shell) must not run for it, and an `OptIn` handler would serve the proven
/// key everything it serves a stranger.
#[test]
fn served_mint_refuses_a_proven_origin_for_never_and_optin() {
    assert!(
        Served::<GatedNoop>::mint(proven_witness()).is_err(),
        "a proven witness cannot mint a Never handler's proof"
    );
    assert!(
        Served::<OpenNoop>::mint(proven_witness()).is_err(),
        "a proven witness cannot mint an OptIn handler's proof"
    );
}

/// The same wall at the dispatcher's seam: the erased bridge refuses a proven witness for a `Never` and an
/// `OptIn` handler before any success, with the uniform refusal, and reads the same rule at construction.
#[test]
fn never_and_optin_refuse_a_proven_origin() {
    assert!(
        matches!(
            GatedNoop.prepare(proven_witness()),
            Err(Refusal::NotAdmitted)
        ),
        "a Never handler refuses a proven witness before any success"
    );
    assert!(
        matches!(
            OpenNoop.prepare(proven_witness()),
            Err(Refusal::NotAdmitted)
        ),
        "an OptIn handler refuses a proven witness before any success"
    );
    assert!(!GatedNoop.accepts(Origin::Proven));
    assert!(!OpenNoop.accepts(Origin::Proven));
    assert!(ProvenNoop.accepts(Origin::Proven));
}

/// A `ProvenOnly` handler accepts a proven witness and nothing else: a rooted one would let a member's
/// token reach a route built for keys with no standing, and an open one would let an unproven stranger
/// reach it.
#[test]
fn a_proven_only_handler_refuses_rooted_and_open() {
    assert!(
        Served::<ProvenNoop>::mint(proven_witness()).is_ok(),
        "a proven witness mints a ProvenOnly handler's proof"
    );
    assert!(
        Served::<ProvenNoop>::mint(witness(true)).is_err(),
        "a rooted witness cannot mint a ProvenOnly handler's proof"
    );
    assert!(
        Served::<ProvenNoop>::mint(witness(false)).is_err(),
        "an open witness cannot mint a ProvenOnly handler's proof"
    );
    assert!(!ProvenNoop.accepts(Origin::Rooted));
    assert!(!ProvenNoop.accepts(Origin::Open));
}

/// A proven proof never narrows to a rooted one: an engine whose safety rests on a verified peer cannot be
/// handed a key that holds no standing here.
#[test]
fn into_rooted_refuses_a_proven_origin() {
    let proven = Served::<ProvenNoop>::mint(proven_witness())
        .expect("a proven witness mints a ProvenOnly proof")
        .into_rooted();
    assert!(
        matches!(proven, Err(ServeError::OpenAdmission)),
        "a proven witness cannot narrow to a rooted token"
    );
}
