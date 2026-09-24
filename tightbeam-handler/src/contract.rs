//! The contract items: one marker, one metering, one serve, and the proof that binds them.

use core::future::Future;
use core::marker::PhantomData;

use bifrost_core::Refusal;
use nauthy::{Admission, Admitted, Origin, VerifyKey};
use tokio::io;

use crate::open_policy::{self, Compatible, PublicUse};

/// A boxed writer half handed to a handler (the accepted stream is already `Send + 'static`, so boxing it
/// as a trait object is a small per-stream allocation, invisible next to the splice it feeds).
pub type BoxWrite = Box<dyn io::AsyncWrite + Unpin + Send>;
/// A boxed reader half handed to a handler.
pub type BoxRead = Box<dyn io::AsyncRead + Unpin + Send>;

/// What a service handler declares about its responder-side rate limit: whether it bounds what a caller may
/// consume, or answers any caller with no bound.
///
/// A handler property, read from its constructor config at [`Handler::metering`] and rendered by a caller's
/// readiness manifest. It is a CAVEAT a banner narrates, never a security gate: an open service whose handler
/// is [`Unmetered`](Metering::Unmetered) lets an anonymous stranger drain the node's uplink, so the banner
/// says so where the danger is. The default is [`Unmetered`](Metering::Unmetered) (the fail-loud direction: a
/// handler that does not state a bound warns when opened), and a handler that enforces one overrides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metering {
    /// The handler bounds what one caller (or all callers) may consume before it refuses, or cannot answer
    /// with more than it receives (a symmetric reflector).
    Metered,
    /// The handler answers any caller with no responder-side bound, so an OPEN one is drainable.
    Unmetered,
}

/// Why a handler stopped serving one admitted stream. Typed (`thiserror`), library vocabulary; a binary
/// consumer maps it to `eyre` at its verb edge.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The gate (or a proof's ceiling) refused the request. The typed [`Refusal`] classification travels
    /// unchanged, so a caller matches it instead of parsing text.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// A rooted witness is required for this serving proof, but the gate admitted by an open policy or
    /// witnessed a proven key with no token. Produced only by [`Served::into_rooted`], for an engine whose
    /// safety precondition is a verified peer.
    #[error("this service requires a rooted admission")]
    OpenAdmission,
    /// The stream failed at the transport level.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A service handler: what to DO with one admitted stream. A dispatcher knows only this CONTRACT (a name maps
/// to a thing that consumes an admitted stream), never what a handler does; a caller that depends on the
/// service crates implements it. The handler receives a [`Served<Self>`](Served) proof by value: it carries
/// the gate's single-use [`Admitted`] witness, so "authorize before serve" is a compile-time precondition,
/// plus the stream halves for ONE stream.
///
/// Whether the handler may EVER face an unauthenticated stranger is a COMPILE-TIME property, stated once as
/// the associated [`type Exposure`](Handler::Exposure): a keyless shell names
/// [`Never`](crate::open_policy::Never) (an open gate over it is refused when the proof is prepared), a
/// legitimately-public responder names [`OptIn`](crate::open_policy::OptIn), and a service that answers a
/// proven key with no standing names [`ProvenOnly`](crate::open_policy::ProvenOnly). There is no default and no
/// runtime bool: omitting the choice does not compile, and the marker is sealed + uninhabited, so "a keyless
/// service mislabeled open" is unrepresentable rather than a guarded default.
///
/// The `serve` future is `+ Send`: a dispatcher may run it on a multi-thread runtime and hold the boxed serve
/// future across `.await`, so it must be `Send`, and the compiler enforces it. Authors may still write a
/// plain `async fn serve` whose body is `Send`; on the pinned toolchain that coerces to the `+ Send` RPITIT
/// bound at the impl site with no `trait_variant` needed. `where Self: Sized` is compiler-forced by
/// [`Served<Self>`](Served).
pub trait Handler: Send + Sync + 'static {
    /// This handler's open-safety CEILING, stated as a type (no default, so the author MUST pick one of
    /// [`Never`](crate::open_policy::Never) / [`OptIn`](crate::open_policy::OptIn) /
    /// [`ProvenOnly`](crate::open_policy::ProvenOnly)). Read when the proof is prepared, to refuse a witness
    /// whose origin the marker does not accept, and erased at the
    /// [`ErasedHandler`](crate::bridge::ErasedHandler) bridge for a dispatcher's construction checks.
    type Exposure: PublicUse;

    /// The responder-side rate limit this handler enforces, read from its constructor config so a banner
    /// renders the running policy rather than a frozen flag. The default is [`Metering::Unmetered`]: a
    /// handler that does not state a bound is narrated as unbounded when opened, the fail-loud direction.
    /// Erased to [`ErasedHandler::metering`](crate::bridge::ErasedHandler::metering) and read when a
    /// dispatcher builds its readiness manifest.
    fn metering(&self) -> Metering {
        Metering::Unmetered
    }

    /// Serve ONE admitted stream: the handler-bound [`Served<Self>`](Served) proof (carrying the gate's
    /// single-use witness) and the stream halves.
    fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> impl Future<Output = Result<(), ServeError>> + Send
    where
        Self: Sized;
}

/// A serving proof for the concrete handler `H`, carrying the gate's single-use [`Admitted`] witness.
///
/// Private fields, no public constructor, `!Clone`/`!Copy`: the only mint is the crate-private `mint`,
/// reached by the erased bridge's `prepare` (for the registered `H`) and by the bounded
/// [`delegate`](Served::delegate) conversion. It binds the proof to the HANDLER TYPE (never to a service or
/// a stream): the same handler under two names shares the type, and the proof still carries one per-stream
/// witness.
///
/// The proof is minted only when the handler's marker accepts the witness's origin: a `Never` handler
/// requires a rooted one ([`Origin::Rooted`](nauthy::Origin::Rooted)), an `OptIn` handler also accepts an
/// open one, and a `ProvenOnly` handler accepts a proven one ([`Origin::Proven`](nauthy::Origin::Proven))
/// and nothing else. No other marker accepts a proven witness. That refusal happens before any success
/// response because preparation is monomorphized on the concrete `H`.
///
/// A laundering delegation is a compile error, not a runtime refusal: `delegate` requires
/// `H::Exposure: Compatible<I::Exposure>`, and `OptIn` is not compatible with `Never`, nor `ProvenOnly`
/// with any other marker.
///
/// ```compile_fail
/// use tightbeam_handler::open_policy::{Never, OptIn};
/// use tightbeam_handler::{BoxRead, BoxWrite, Handler, ServeError, Served};
///
/// struct Outer;
/// struct Shell;
///
/// impl Handler for Outer {
///     type Exposure = OptIn;
///     async fn serve(
///         &self,
///         _served: Served<Self>,
///         _writer: BoxWrite,
///         _reader: BoxRead,
///     ) -> Result<(), ServeError> {
///         Ok(())
///     }
/// }
///
/// impl Handler for Shell {
///     type Exposure = Never;
///     async fn serve(
///         &self,
///         _served: Served<Self>,
///         _writer: BoxWrite,
///         _reader: BoxRead,
///     ) -> Result<(), ServeError> {
///         Ok(())
///     }
/// }
///
/// // An `OptIn` proof cannot be delegated into a `Never` inner: E0277 `OptIn: Compatible<Never>`.
/// fn launder(served: Served<Outer>) {
///     let _ = served.delegate::<Shell>();
/// }
/// ```
///
/// A proven proof cannot be delegated into a `Never` inner either, so a handler built for a proven key can
/// never hand its witness to a keyless shell:
///
/// ```compile_fail
/// use tightbeam_handler::open_policy::{Never, ProvenOnly};
/// use tightbeam_handler::{BoxRead, BoxWrite, Handler, ServeError, Served};
///
/// struct Proven;
/// struct Shell;
///
/// impl Handler for Proven {
///     type Exposure = ProvenOnly;
///     async fn serve(
///         &self,
///         _served: Served<Self>,
///         _writer: BoxWrite,
///         _reader: BoxRead,
///     ) -> Result<(), ServeError> {
///         Ok(())
///     }
/// }
///
/// impl Handler for Shell {
///     type Exposure = Never;
///     async fn serve(
///         &self,
///         _served: Served<Self>,
///         _writer: BoxWrite,
///         _reader: BoxRead,
///     ) -> Result<(), ServeError> {
///         Ok(())
///     }
/// }
///
/// // E0277 `ProvenOnly: Compatible<Never>`.
/// fn launder(served: Served<Proven>) {
///     let _ = served.delegate::<Shell>();
/// }
/// ```
///
/// ```compile_fail
/// use tightbeam_handler::Served;
///
/// // The proof has private fields: an external crate cannot construct one (E0603/E0451/E0624).
/// fn forge<H: tightbeam_handler::Handler>() -> Served<H> {
///     Served::mint(todo!()).unwrap()
/// }
/// ```
#[must_use = "a Served proof is single-use; serve the one stream it was prepared for"]
pub struct Served<H: Handler + ?Sized> {
    admitted: Admitted,
    /// `fn(&H)` keeps the auto traits independent of `H` while naming it; `?Sized` H needs an indirection,
    /// and a function pointer is never called, only carried.
    handler: PhantomData<fn(&H)>,
}

impl<H: Handler + ?Sized> Served<H> {
    /// The only mint: crate-private, reached by the erased bridge's `prepare` (for the registered `H`) and
    /// by [`delegate`](Served::delegate). Refuses a witness whose origin `H`'s marker does not accept,
    /// fail-closed.
    pub(crate) fn mint(admitted: Admitted) -> Result<Self, Refusal> {
        if !open_policy::accepts::<H::Exposure>(admitted.origin()) {
            return Err(Refusal::NotAdmitted);
        }
        Ok(Self {
            admitted,
            handler: PhantomData,
        })
    }

    /// The identity the gate admitted: verified on a rooted route ([`origin`](Self::origin) is
    /// [`Origin::Rooted`]), proven by the transport but holding no standing on a proven route
    /// ([`Origin::Proven`]), the key the peer announced on an open route ([`Origin::Open`]). A per-caller
    /// policy that needs proof checks the origin first.
    pub fn peer(&self) -> VerifyKey {
        self.admitted.peer()
    }

    /// By WHAT authority the gate admitted the peer (a whole-node member badge or a per-service slip).
    pub fn kind(&self) -> Admission {
        self.admitted.kind()
    }

    /// Whether the peer was admitted as a whole-node member. False on an open node.
    pub fn is_member(&self) -> bool {
        self.admitted.is_member()
    }

    /// How the gate minted the witness (a rooted token ruling, an open admit, or a proven key).
    pub fn origin(&self) -> Origin {
        self.admitted.origin()
    }

    /// The one narrowing seam: hand the ROOTED witness to a proof-free engine. Fails with
    /// [`ServeError::OpenAdmission`] when the witness is not rooted (an open admit or a proven key), so an
    /// engine whose safety precondition is a verified peer cannot be handed either.
    pub fn into_rooted(self) -> Result<RootedAdmitted, ServeError> {
        if !matches!(self.admitted.origin(), Origin::Rooted) {
            return Err(ServeError::OpenAdmission);
        }
        Ok(RootedAdmitted {
            admitted: self.admitted,
        })
    }

    /// Hand this proof inward to the inner handler `I`, preserving the witness and re-applying `I`'s
    /// ceiling. The `Compatible` bound is the compile-time wall (an `OptIn` proof cannot name a `Never`
    /// target); the re-mint is the fail-closed runtime backstop.
    pub fn delegate<I>(self) -> Result<Served<I>, ServeError>
    where
        I: Handler,
        H::Exposure: Compatible<I::Exposure>,
    {
        Served::<I>::mint(self.admitted).map_err(ServeError::from)
    }
}

/// A gate witness narrowed to a ROOTED admission: the engine seam for a service whose safety precondition is
/// that the gate verified a token (a keyless shell). Private field, no public constructor: the only mint is
/// [`Served::into_rooted`], which consumes a handler-bound proof, so an engine that demands this type cannot
/// be reached with an open or a proven witness.
#[derive(Debug)]
#[must_use = "a RootedAdmitted witness proves a rooted gate ruling; serve the one stream it authorized"]
pub struct RootedAdmitted {
    admitted: Admitted,
}

impl RootedAdmitted {
    /// The verified identity the gate admitted.
    pub fn peer(&self) -> VerifyKey {
        self.admitted.peer()
    }

    /// By WHAT authority the gate admitted the peer.
    pub fn kind(&self) -> Admission {
        self.admitted.kind()
    }

    /// Whether the peer was admitted as a whole-node member.
    pub fn is_member(&self) -> bool {
        self.admitted.is_member()
    }

    /// Consume the rooted proof back into the gate witness it wraps: the transitional seam for an engine
    /// that still takes the untyped [`Admitted`]. No authority is added: this type is minted only by
    /// [`Served::into_rooted`], which refuses every witness that is not rooted, so the witness handed on is
    /// rooted by construction. Deleted when the engine takes `RootedAdmitted` directly.
    pub fn into_admitted(self) -> Admitted {
        self.admitted
    }
}
