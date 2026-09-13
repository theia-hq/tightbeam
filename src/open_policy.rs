//! The open-safety marker family a [`Handler`](crate::tunnel::Handler) declares: does this service have a
//! legitimate PUBLIC use, or must it never face an unauthenticated stranger?
//!
//! The markers moved to the lean `tightbeam-handler` crate (delib-56 verdict 13) so a service crate can name
//! its ceiling without taking this crate's tree; this module re-exports them unchanged, keeping every
//! `tightbeam::open_policy::*` path working. The definitions, the seal, and the compile-fail probe live in
//! `tightbeam_handler::open_policy`.

pub use tightbeam_handler::open_policy::{Compatible, Never, OptIn, PublicUse};
