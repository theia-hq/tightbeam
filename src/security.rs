//! The transport-security rule tightbeam enforces: a credential moves only toward a peer the transport
//! proves.
//!
//! A transport declares what it proves and protects as a [`SecurityProfile`](bifrost::SecurityProfile).
//! tightbeam reads that declaration at the seams that cash it: the checked credential writer
//! ([`Request::write_checked`](crate::protocol::Request::write_checked)), so a credential never leaves a
//! client toward a self-announced peer; the rooted admission decision, so an announced session never mints
//! a proven witness; and the construction refusal
//! ([`Exposer::prove_security`](crate::tunnel::Exposer::prove_security)), so a rooted gate never arms over
//! a transport it could not admit from. The compile-time half lives on
//! [`PresentingConnector`](crate::tunnel::PresentingConnector), whose dial methods require the declared
//! profile to satisfy [`PeerProven`](bifrost::PeerProven).
//!
//! The declaration is a claim, not a proof: these seams enforce that the claim covers what a path needs,
//! never that the claim is true. What backs a profile is the transport's handshake and the conformance
//! suite; see `bifrost_transport::security`.

use bifrost::{PeerProof, Security};

/// Whether a declared [`Security`] proves the peer holds the private key for the `NodeId` it is reached
/// under: the ONE predicate both enforcement seams consult.
///
/// [`PeerProof::Proven`] is a completed handshake; [`PeerProof::InProcess`] is exact by construction (the
/// bytes never cross a trust boundary). [`PeerProof::Announced`] is a claim the peer made about itself.
pub(crate) fn peer_proven(security: Security) -> bool {
    matches!(security.peer, PeerProof::Proven | PeerProof::InProcess)
}

/// The peer-proof claim as the lowercase word a teaching message uses.
pub(crate) fn proof_label(proof: &PeerProof) -> &'static str {
    match proof {
        PeerProof::Proven => "proven",
        PeerProof::InProcess => "in-process",
        PeerProof::Announced => "announced",
    }
}

/// A credential was about to be written over a transport that does not prove the peer.
///
/// The transport declared [`PeerProof::Announced`], so the key the session reports is a claim, not a
/// proof: presenting a credential would hand it to whoever answers the dial. Nothing was written.
#[derive(Debug, thiserror::Error)]
#[error(
    "the transport does not prove the peer (declared: {}); presenting a credential would send it to \
     whoever answers",
    proof_label(.declared)
)]
pub struct TransportInsecure {
    /// The peer-identity claim the session's transport declared.
    pub declared: PeerProof,
}
