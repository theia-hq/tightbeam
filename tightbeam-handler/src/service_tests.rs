//! The two properties that make the typed door an OPT-IN rather than a migration, and the one that
//! makes it safe: a typed service and a raw handler store side by side in ONE erased route table, the
//! sealed exposure ceiling forwards through the adapter unchanged, and the raw halves reach the service
//! positioned at the payload's first byte with nothing stranded.

// `Cursor` lives in `std::io`: the lint's `core::io` spelling is still unstable (rustc 1.97).
#![allow(clippy::std_instead_of_core)]

use core::future::Future;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::io::Cursor;
use std::sync::Arc;

use bifrost_core::Refusal;
use nauthy::{Gate, ProvenPeer};
use tokio::io::{self, AsyncReadExt as _};

use crate::bridge::ErasedHandler;
use crate::open_policy::{Never, OptIn, PublicUse};
use crate::wire::{Frame, WireError};
use crate::{BoxRead, BoxWrite, Handler, Metering, Serve, ServeError, Served, Service};

/// Drive a future to completion on this thread: the halves here are in-memory and always ready, so
/// nothing parks and the contract crate stays runtime-free.
fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

/// Mint an admission witness through the only public mint (the gate). `rooted` picks a rooted gate with
/// a member badge against an open gate admitting a stranger.
fn witness(rooted: bool) -> nauthy::Admitted {
    let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
    let peer = nauthy::Identity::from_secret(&[5u8; 32])
        .expect("valid secret")
        .verifying_key();
    let service: nauthy::Service = "typed".parse().expect("valid service name");
    if rooted {
        let badge = signet
            .mint_member(peer, nauthy::Request::expires_in(Duration::from_secs(300)))
            .expect("mint a member badge");
        let gate = Gate::rooted(
            signet.verifying_key(),
            nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-handler-typed-rooted")),
        );
        gate.admit_witnessed(ProvenPeer::from_handshake(peer), Some(&badge), &service)
            .expect("a member badge admits")
    } else {
        Gate::Open
            .admit_witnessed(ProvenPeer::from_handshake(peer), None, &service)
            .expect("an open gate admits anyone")
    }
}

/// The smallest honest control preamble: four magic bytes and a one-byte selector, fixed width, so the
/// head IS the whole frame.
#[derive(Debug, PartialEq, Eq)]
struct Open(u8);

/// A selector this build has no behaviour for.
#[derive(Debug, thiserror::Error)]
#[error("unknown selector {0:#04x}")]
struct UnknownSelector(u8);

impl Frame for Open {
    const MAX: usize = 5;
    const HEAD: usize = 5;

    fn rest(_head: &[u8]) -> usize {
        0
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"TYP1");
        out.push(self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes[..4] != *b"TYP1" {
            return Err(WireError::malformed(UnknownSelector(bytes[0])));
        }
        Ok(Self(bytes[4]))
    }
}

/// A typed service with a legitimate public use: it records the selector it was handed and drains the
/// raw reader, which is what a body-streaming service does next.
struct OpenTyped {
    selector: Arc<AtomicBool>,
    payload: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl OpenTyped {
    fn new() -> Self {
        Self {
            selector: Arc::new(AtomicBool::new(false)),
            payload: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

impl Service for OpenTyped {
    type Exposure = OptIn;
    type Request = Open;

    fn metering(&self) -> Metering {
        Metering::Metered
    }

    async fn respond(
        &self,
        _served: Served<Serve<Self>>,
        request: Open,
        _writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        self.selector.store(request.0 == 9, Ordering::SeqCst);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await?;
        if let Ok(mut held) = self.payload.lock() {
            *held = rest;
        }
        Ok(())
    }
}

/// A typed service with NO legitimate public use: the ceiling an adapter must not soften.
struct GatedTyped;

impl Service for GatedTyped {
    type Exposure = Never;
    type Request = Open;

    async fn respond(
        &self,
        _served: Served<Serve<Self>>,
        _request: Open,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// A RAW handler: no frame of its own, implemented against the floor exactly as a splicing service is
/// today. It never names `Service`, which is the whole opt-out.
struct RawSplice;

impl Handler for RawSplice {
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        // The narrowing seam a keyless engine demands still works from the raw door.
        let _rooted = served.into_rooted()?;
        Ok(())
    }
}

/// The ceiling forwards as a TYPE, so it is frozen at build time rather than checked at run time.
/// Flipping either association would let an uncapped service face an open gate, or gate one an operator
/// may deliberately open.
const _: () = assert!(<<Serve<OpenTyped> as Handler>::Exposure as PublicUse>::OPEN_SAFE);
const _: () = assert!(!<<Serve<GatedTyped> as Handler>::Exposure as PublicUse>::OPEN_SAFE);
const _: () = assert!(!<<RawSplice as Handler>::Exposure as PublicUse>::OPEN_SAFE);

/// The opt-in property: a typed service and a raw handler are stored in ONE erased route table and the
/// dispatcher reads each one's ceiling and metering without naming either's traits. If the typed layer
/// needed its own storage it would be a migration, not a library.
#[test]
fn a_typed_service_and_a_raw_handler_share_one_erased_store() {
    let store: Vec<Arc<dyn ErasedHandler>> = vec![
        Arc::new(Serve(OpenTyped::new())),
        Arc::new(Serve(GatedTyped)),
        Arc::new(RawSplice),
    ];

    assert!(store[0].open_safe(), "the typed OptIn service is openable");
    assert!(!store[1].open_safe(), "the typed Never service is not");
    assert!(!store[2].open_safe(), "and neither is the raw handler");
    assert_eq!(store[0].metering(), Metering::Metered);
    assert_eq!(
        store[1].metering(),
        Metering::Unmetered,
        "the trait default rides through the adapter, fail-loud"
    );
}

/// The sealed ceiling survives the adapter AT RUN TIME as well as at build time: the erased bridge
/// refuses an open witness for a typed `Never` service before any success response can exist, exactly
/// as it does for a raw one, and still mints for a rooted witness and for a typed `OptIn` service.
///
/// This is the test that catches a silent downgrade. Write `type Exposure = OptIn;` in the adapter
/// instead of `S::Exposure` and the two `const _` assertions above stop compiling and this goes red:
/// a stranger would reach a service whose author said never.
#[test]
fn the_sealed_ceiling_forwards_through_the_adapter() {
    let gated = Serve(GatedTyped);
    assert!(
        matches!(gated.prepare(witness(false)), Err(Refusal::NotAdmitted)),
        "an open witness is refused for a typed Never service, before any success"
    );
    assert!(
        gated.prepare(witness(true)).is_ok(),
        "a rooted witness mints the typed Never service's proof"
    );
    assert!(
        Serve(OpenTyped::new()).prepare(witness(false)).is_ok(),
        "an open witness mints a typed OptIn service's proof"
    );
    // The raw door is unchanged beside it, which is the point of leaving the floor alone.
    assert!(
        matches!(RawSplice.prepare(witness(false)), Err(Refusal::NotAdmitted)),
        "the raw handler's ceiling is refused the same way"
    );
}

/// The adapter reads the preamble and hands back the RAW halves by value, positioned at the payload's
/// first byte. A service that streams, counts, or splices from here is never forced through a codec,
/// and nothing has to be replayed into it.
#[test]
fn the_service_receives_the_decoded_request_and_the_raw_halves() {
    const PAYLOAD: &[u8] = b"the body this service would splice";
    let service = OpenTyped::new();
    let selector = Arc::clone(&service.selector);
    let payload = Arc::clone(&service.payload);

    let mut stream = Vec::new();
    Open(9).encode(&mut stream);
    stream.extend_from_slice(PAYLOAD);

    let handler = Serve(service);
    let prepared = handler
        .prepare(witness(false))
        .expect("an open witness mints an OptIn proof");
    run(prepared.serve(Box::new(io::sink()), Box::new(Cursor::new(stream))))
        .expect("the typed service serves the stream");

    assert!(
        selector.load(Ordering::SeqCst),
        "the service received its request DECODED, not as bytes"
    );
    assert_eq!(
        payload
            .lock()
            .expect("the payload mutex is not poisoned")
            .as_slice(),
        PAYLOAD,
        "and the raw reader was positioned at the payload's first byte"
    );
}

/// A preamble this build cannot read ends the stream rather than reaching the service with a guessed
/// request: the adapter's one read is the gate between bytes and a typed value.
#[test]
fn an_unreadable_preamble_never_reaches_the_service() {
    let service = OpenTyped::new();
    let selector = Arc::clone(&service.selector);
    let handler = Serve(service);
    let prepared = handler
        .prepare(witness(false))
        .expect("an open witness mints an OptIn proof");
    let served = run(prepared.serve(
        Box::new(io::sink()),
        Box::new(Cursor::new(b"XXXX\x09".to_vec())),
    ));
    assert!(
        matches!(served, Err(ServeError::Io(_))),
        "a foreign preamble fails the stream"
    );
    assert!(
        !selector.load(Ordering::SeqCst),
        "and the service body never ran"
    );
}
