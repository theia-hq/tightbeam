//! The erased bridge: the dispatcher's view of a [`Handler`], and the only mint of a serving proof.
//!
//! A dispatcher stores heterogeneous handlers and must read each one's ceiling and metering WITHOUT naming
//! its associated marker. [`ErasedHandler`] is that object-safe view: the marker erases to a frozen
//! `const bool`, and the RPITIT serve future boxes into a `Send`-bearing trait object. The bridge also splits
//! preparation from serving so the ceiling refusal lands BEFORE a success response: `prepare` is
//! monomorphized on the concrete `H`, mints the handler-bound [`Served<H>`](crate::Served) (refusing a witness
//! whose origin the handler's marker does not accept), and freezes the serve step into an opaque
//! [`Prepared`] closure. A dispatcher runs `prepare`, writes its success response only on `Ok`, then runs the
//! prepared closure.
//!
//! The closure form is required: the erased prepared value must not let safe code outside this crate re-pair
//! the witness with another handler's serve. The proof's mint is crate-private, so every constructor here is
//! the checked predicate, and the blanket impl covers exactly the handlers the contract admits.

use core::future::Future;
use core::pin::Pin;

use bifrost_core::Refusal;
use nauthy::{Admitted, Origin};

use crate::contract::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};
use crate::open_policy::{self, PublicUse};

/// The object-safe, stored-in-the-route view of a [`Handler`]: the associated `Exposure` marker is erased
/// here to a `const bool` ([`open_safe`](ErasedHandler::open_safe)) and the RPITIT `serve` future is boxed
/// ([`Prepared::serve`], `Send`-bearing), so heterogeneous handlers (a
/// [`Never`](crate::open_policy::Never) and an [`OptIn`](crate::open_policy::OptIn) handler) share ONE
/// `Arc<dyn ErasedHandler>` storage type. The marker
/// never enters these signatures, so it does its job at the impl-site type-check and then vanishes into the
/// object's frozen `open_safe()` answer. An associated type survives erasure as a const the trait object
/// still carries; a generic would have to be chosen at the storage site, which is exactly where the
/// handler author is absent.
///
/// SEALED: the blanket impl below is the only impl, because the private supertrait closes the set. A
/// downstream crate cannot mint a [`Prepared`] anyway (private fields), so the seal states the invariant
/// rather than guarding a live hole.
pub trait ErasedHandler: sealed::Sealed + Send + Sync {
    /// The erased open-safety ceiling: `<H::Exposure as PublicUse>::OPEN_SAFE`, read before any success
    /// response.
    fn open_safe(&self) -> bool;
    /// The erased origin rule: whether this handler's marker accepts a witness of `origin`, the same rule
    /// [`prepare`](ErasedHandler::prepare) applies. Read at construction, so a route that could never mint
    /// its handler's proof is refused before it serves.
    fn accepts(&self, origin: Origin) -> bool;
    /// The erased responder-side metering: [`Handler::metering`], read when a dispatcher builds its
    /// manifest.
    fn metering(&self) -> Metering;
    /// The pre-success half: mint the handler-bound proof and freeze the post-success serve into a
    /// [`Prepared`]. A refusal here is a payload-free [`Refusal`] the caller can write to the wire before any
    /// success.
    fn prepare<'a>(&'a self, admitted: Admitted) -> Result<Prepared<'a>, Refusal>;
}

/// The frozen post-success serve step: the handler's typed proof and the erased serve future, captured in one
/// opaque closure. Private fields, no accessor back to the [`Admitted`] witness, so safe code outside this
/// crate cannot re-pair the witness with another handler's serve (the laundering the closure form exists to
/// close).
type PreparedRun<'a> = dyn FnOnce(BoxWrite, BoxRead) -> BoxServe<'a> + Send + 'a;

/// The boxed serve future the bridge freezes: `Send` and `'a` (borrowing the handler the proof was minted
/// for).
type BoxServe<'a> = Pin<Box<dyn Future<Output = Result<(), ServeError>> + Send + 'a>>;

/// The frozen post-success serve step, opaque to a dispatcher: run [`serve`](Prepared::serve) with the
/// stream halves and await the handler's future.
#[must_use = "a prepared serve step serves nothing until `Prepared::serve` runs"]
pub struct Prepared<'a> {
    serve: Box<PreparedRun<'a>>,
}

impl<'a> Prepared<'a> {
    /// Run the frozen serve step for ONE stream, borrowing the handler for `'a`.
    pub fn serve(
        self,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> impl Future<Output = Result<(), ServeError>> + Send + 'a {
        (self.serve)(writer, reader)
    }
}

impl<H: Handler> ErasedHandler for H {
    fn open_safe(&self) -> bool {
        <H::Exposure as PublicUse>::OPEN_SAFE
    }

    fn accepts(&self, origin: Origin) -> bool {
        open_policy::accepts::<H::Exposure>(origin)
    }

    fn metering(&self) -> Metering {
        Handler::metering(self)
    }

    fn prepare<'a>(&'a self, admitted: Admitted) -> Result<Prepared<'a>, Refusal> {
        let served = Served::<H>::mint(admitted)?;
        Ok(Prepared {
            serve: Box::new(move |writer, reader| {
                Box::pin(Handler::serve(self, served, writer, reader))
            }),
        })
    }
}

/// Seals [`ErasedHandler`] to the blanket impl in this module: a downstream crate cannot implement the
/// dispatcher's view for a type of its own, so the erased storage set is closed to `Handler` impls.
mod sealed {
    pub trait Sealed {}

    impl<H: super::Handler> Sealed for H {}
}
