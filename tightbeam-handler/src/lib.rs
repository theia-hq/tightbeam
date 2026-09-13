//! The tightbeam handler contract: what a service implements to serve one admitted stream.
//!
//! A node binds a name to a value that implements [`Handler`]. Once the gate admits a stream and the
//! dispatcher prepares the handler's proof, the handler receives a [`Served<Self>`](Served) carrying the
//! gate's single-use [`Admitted`](nauthy::Admitted) witness plus the two boxed stream halves, and returns a
//! future that serves the one stream. The handler never learns how the peer was reached, only what the gate
//! admitted: it reads [`Served::peer`](Served::peer), [`Served::kind`](Served::kind), and the origin when its
//! own policy needs a finer floor.
//!
//! Whether a handler may EVER face an unauthenticated stranger is a compile-time property, stated once as
//! [`Handler::Exposure`](Handler::Exposure): [`Never`](open_policy::Never) for a service with no legitimate
//! public use (a keyless shell), [`OptIn`](open_policy::OptIn) for one the operator may deliberately open.
//! The markers are sealed and uninhabited, so the choice cannot be omitted, defaulted, or named by a third
//! variant. [`Compatible`](open_policy::Compatible) is the one-way relation a proof conversion is bounded
//! by: a proof may narrow into a compatible inner handler, never widen.
//!
//! This crate is deliberately lean: [`nauthy`] for the witness, `bifrost-core` for the typed refusal, and
//! the stream-trait halves. It names no transport backend, no gate policy, and no dispatcher; [`tightbeam`]
//! depends on it and re-exports every public item at its original path, so a service crate implements the
//! contract without taking tightbeam's own non-optional backends and CLI tree.
//!
//! The erased bridge in [`bridge`] is the dispatcher's view (heterogeneous storage plus the pre-`Ok`
//! preparation split); a service author never names it.

pub mod bridge;
mod contract;
pub mod open_policy;

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod open_policy_tests;

pub use contract::{BoxRead, BoxWrite, Handler, Metering, RootedAdmitted, ServeError, Served};
