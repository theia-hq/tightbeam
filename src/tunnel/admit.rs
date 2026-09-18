//! Admission: who may reach a named service on this node, and the one uniform refusal a dialer who may
//! not gets.
//!
//! [`resolve_gate`] is the policy every embedder roots its node on; [`admit`] rules one stream under it
//! (composed with the two open overlays and the public-path caps) and [`serve_request`] carries that
//! ruling to the wire, writing the payload-free refusal for every class of miss so the wire is no oracle.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use bifrost::{NodeId, PeerProof, Refusal, RefusalDetail};
use nauthy::{Admitted, Cap, FileDenylist, Gate, ProvenPeer, Service};
use tokio::io;
use tokio::sync::OwnedSemaphorePermit;

use super::exposer::{PublicPool, PublicSession, Serving, SessionPeer};
use super::router::{Access, PublicServices, Route, Services, Target};
use crate::identity::AsVerifyKey as _;
use crate::protocol::{Request, Response};
use crate::security::{peer_proven, proof_label};
use crate::splice_halves;

/// Resolve the exposer's node BASE gate, in ONE place so every embedder applies the SAME policy: a family
/// gate on the node's provisioned `signet`; an UNPROVISIONED
/// node fails LOUD rather than ever defaulting to open. The caller loads the denylist and passes it as a
/// value. This exists so the two security-relevant conventions (fail-loud-on-unprovisioned,
/// real-loaded-denylist) are enforced once, not hand-copied into each caller.
///
/// The base gate is the node-wide FAMILY authority; opening individual services is a SEPARATE, per-service
/// overlay ([`Router::public`](super::Router::public)), never a node-wide value this function returns.
/// Building a node-wide [`Gate::Open`] base is a caller's own deliberate choice (nauthy's
/// [`Gate::Open`]), not something a
/// gate-resolution policy hands back from a flag: that node-wide-open flag was exactly the whole-node blast
/// radius per-service exposure removes.
pub fn resolve_gate(signet: Option<NodeId>, denylist: FileDenylist) -> eyre::Result<Gate> {
    let root = signet.ok_or_else(|| {
        eyre::eyre!(
            "this node has no signet to gate on: provision it (adopt a signet), or open individual services \
             to anyone"
        )
    })?;
    Ok(Gate::rooted(root.verify_key(), denylist))
}

/// How long to wait for a connector to send its opening request before dropping the stream. Bounds the
/// pre-gate work an unauthenticated peer can pin (a slow-loris that opens a stream and never speaks).
pub(super) const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve one inbound stream: read the request, apply the gate, reply, and pipe on success.
///
/// The gate decides per stream, not per session, because the requested service (and any presented
/// capability) is a property of the stream: one session may carry several service requests, each gated on
/// its own merits. `public_session` is this session's half of the public cap: a stream that
/// takes the public path classifies the session, and the permit it carries rides this future to the end.
pub(super) async fn serve_request<W, R>(
    peer: SessionPeer,
    mut writer: W,
    mut reader: R,
    serving: Arc<Serving>,
    public_session: Arc<PublicSession>,
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin + Send + 'static,
    R: io::AsyncRead + Unpin + Send + 'static,
{
    let Serving {
        gate,
        public,
        public_unsafe,
        services,
        raw_stream_opens,
        public_pool,
        enabled,
    } = &*serving;
    let Services(services) = services;
    // Bound the pre-gate read: a peer that opens a stream but never sends its request would otherwise
    // park this task (and its buffer) indefinitely, BEFORE the gate runs, so unauthenticated peers could
    // exhaust the node one slow stream at a time. Time out and drop a silent stream.
    let request = match tokio::time::timeout(REQUEST_READ_TIMEOUT, Request::read(&mut reader)).await
    {
        Ok(result) => result?,
        Err(_elapsed) => {
            tracing::warn!(%peer, "request read timed out before the gate; dropping the stream");
            return Ok(());
        }
    };
    let service = match request.service.parse::<Service>() {
        Ok(service) => service,
        Err(error) => {
            // The request's shape is the peer's own grammar, already public, so the wire names it; the
            // host log carries the parse failure for the operator.
            tracing::warn!(%peer, service = %request.service, %error, "invalid service name");
            return Response::Refused(Refusal::BadRequest {
                detail: RefusalDetail::bounded(format!(
                    "invalid service name {:?}",
                    request.service
                )),
            })
            .write(&mut writer)
            .await
            .map_err(Into::into);
        }
    };
    // A node exposing exactly one service should not require the request to name it: if the request names
    // no exposed service (a connector defaulting to `default`) and there is only one, resolve to it. Done
    // BEFORE the gate so a delegated slip for that service still matches (the gate checks the RESOLVED service).
    let service = resolve_single_service(service, services);

    // `admitted` carries the public-stream permit (when this is a public stream) for the WHOLE of this
    // function: the permit field is never moved, so it drops when this stream ends, which is what releases
    // the slot. Its witness is moved on below into `prepare`; the remaining permit field stays bound to the
    // end of this scope.
    let admitted = match admit(
        Admission {
            gate,
            public,
            public_unsafe,
            pool: public_pool,
        },
        public_session.as_ref(),
        peer,
        request.capability.as_deref(),
        request.membership.as_deref(),
        &service,
    ) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            // The full cause (malformed / missing / not-granted / revoked / public capacity, the typed
            // `HostRefusal`) is a LOCAL log line for the node's own operator. The WIRE gets one
            // indistinguishable `Refusal::NotAdmitted`, so a not-admitted dialer cannot tell a stranger's
            // `Missing` from a revoked holder's `Revoked`, nor confirm a service exists at all: no
            // pre-authorization revocation or capability-enumeration oracle. A saturated public pool is
            // wire-identical to a gate miss for the same reason.
            tracing::warn!(%peer, service = %service, %refusal, "refused");
            return Response::Refused(wire_refusal(&refusal))
                .write(&mut writer)
                .await
                .map_err(Into::into);
        }
    };

    // Live enable/disable, consulted POST-admission on the RESOLVED name: a service the operator has
    // disabled refuses here, and a re-enable restores it on the next stream with no restart (the oracle
    // re-reads its backing file on change). The check sits AFTER `admit` so every dialer pays the gate
    // first: a pre-gate check would let a cap-holder time "refused without a gate verify" (disabled)
    // against "refused after one" (enabled or absent) and read the disabled set straight off the clock.
    // The wire gets the SAME indistinguishable
    // refusal a gate miss gives, so a disabled service reads exactly like a gated or absent one: no dialer
    // can tell "disabled" from "not a member", and toggling leaks nothing. An already-open stream to a
    // service disabled mid-flight stays open (next-stream semantics, identical to revocation).
    if !enabled.is_enabled(&service) {
        tracing::warn!(%peer, service = %service, "refused: service disabled");
        return Response::Refused(Refusal::NotAdmitted)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    }

    // The member floor: a route declared `Access::Member` at registration is checked ONCE here,
    // after `admit` and before every `Response::Ok` below, so the check covers every dispatch arm and can
    // still be a WIRE refusal; a handler-side check would run post-`Ok` and the client would read a stopped
    // "success". The witness is BORROWED for `is_member` (`&self`) and stays owned for the single move into
    // the handler, and the refusal is the SAME payload-free class a gate miss gives: the wire never learns
    // that a route is member-only (no member-vs-slip oracle). The lookup is hoisted so the floor and the
    // dispatch below read the same resolved route.
    let route = services.get(service.as_str());
    if route.is_some_and(|route| route.access == Access::Member) && !admitted.witness.is_member() {
        tracing::warn!(%peer, service = %service, "refused: member-only route");
        return Response::Refused(Refusal::NotAdmitted)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    }

    match route.map(|route| &route.target) {
        // tightbeam's own primitive, the raw-stream half: open the source (a guarded file/FIFO, or take fd 0
        // for `stdin:`) and splice its bytes toward the peer. `Response::Ok` is written only AFTER the open
        // succeeds, so a peer learns "refused" (not a silent hang or a mid-stream reset) when the target is a
        // device, a directory, a symlink, a FIFO whose writer never appears, or a `stdin:` already taken by a
        // concurrent connection (the single-consumer refusal).
        Some(Target::RawStream(stream)) => {
            // Take a raw-stream open permit BEFORE opening, as defense-in-depth (the open is nonblocking and
            // cannot park a thread, so this bounds the fds a peer holds mid-open, not a leak): `try_acquire`
            // refuses immediately over the cap rather than admitting one more concurrent open. The permit is
            // held only across the open (the splice below holds none) and dropped when `_permit` leaves scope.
            // See `RAW_STREAM_OPEN_PERMITS`.
            let opened = match raw_stream_opens.try_acquire() {
                Ok(_permit) => stream.open().await,
                Err(_at_cap) => {
                    tracing::warn!(%peer, service = %service, "raw-stream open cap reached; refusing");
                    Err(eyre::eyre!(
                        "the host is opening too many raw streams right now; try again shortly"
                    ))
                }
            };
            match opened {
                Ok(source) => {
                    Response::Ok.write(&mut writer).await?;
                    // Direction is fixed at parse time: read the source, send its bytes to the peer, and
                    // discard any bytes the peer sends upstream (a read-only source has nowhere to put them).
                    // Using `splice_halves` (never the duplex `splice`) is what makes "write peer bytes back
                    // into the source" unrepresentable.
                    splice_halves(source, io::sink(), writer, reader).await?;
                }
                Err(error) => {
                    tracing::warn!(%peer, service = %service, %error, "raw-stream open refused");
                    Response::Refused(Refusal::Unavailable {
                        detail: RefusalDetail::bounded(error.to_string()),
                    })
                    .write(&mut writer)
                    .await?;
                }
            }
        }
        // A bound handler: prepare the handler-bound proof BEFORE any success, then write `Response::Ok`,
        // then run the frozen serve. The proof mint is monomorphized on the concrete handler, so a `Never`
        // handler refuses an open witness HERE, pre-`Ok`, with the same payload-free `NotAdmitted` class a
        // gate miss gives (no never-public oracle). The witness is moved into the proof by value (single-use),
        // so a handler can never run for an unauthorized peer; the guarantee holds only because the admit
        // (above) and this serve share one stream frame, never hoisted to session scope.
        Some(Target::Handler(handler)) => match handler.prepare(admitted.witness) {
            Ok(prepared) => {
                Response::Ok.write(&mut writer).await?;
                prepared.serve(Box::new(writer), Box::new(reader)).await?;
            }
            Err(refusal) => {
                tracing::warn!(
                    %peer,
                    service = %service,
                    %refusal,
                    "refused: unrooted witness for a never-public handler"
                );
                Response::Refused(Refusal::NotAdmitted)
                    .write(&mut writer)
                    .await?;
            }
        },
        None => {
            // Unknown service. The node's OWN log names what it exposes, so a service-name mismatch (the
            // connector defaulting to `default` while the exposer named `web`) is diagnosable by the
            // operator. It must NOT cross the wire: enumerating the service menu to a dialer hands an
            // unauthorized peer the node's capability list before it has proved anything, so the wire gets
            // the same indistinguishable refusal as any not-admitted dial. A dialer learns a service exists only
            // by being admitted to it; the teaching hint returns as the gated `control.services` verb, never
            // as a free menu here. (This arm is reached only past the gate: an Open node, or a whole-node
            // member badge that admits any name -- so uniformity here also stops a member from mapping the
            // menu by probing wrong names, keeping the same rule at every dialer class.)
            let mut available: Vec<&str> = services.keys().map(String::as_str).collect();
            available.sort_unstable();
            tracing::warn!(
                %peer,
                service = %service,
                exposes = %available.join(", "),
                "unknown service requested"
            );
            Response::Refused(Refusal::NotAdmitted)
                .write(&mut writer)
                .await?;
        }
    }
    Ok(())
}

/// Why the host did not admit a stream, in full, for the host's OWN log. It
/// never crosses the wire: the dialer gets one uniform `Refusal::NotAdmitted`,
/// so a stranger cannot tell a missing token from a revoked one, nor confirm an
/// absent name.
#[derive(Debug, thiserror::Error)]
enum HostRefusal {
    /// A presented capability link did not parse. The parse error is the cause;
    /// the wire still says only "not admitted".
    #[error("malformed capability")]
    MalformedCapability(#[source] nauthy::CapError),
    /// The transport does not prove the peer, so a rooted gate cannot rule on the presented token: its
    /// device binding would rest on a key the peer merely announced.
    #[error(
        "the transport does not prove the peer (declared: {}); a rooted gate cannot admit",
        proof_label(.declared)
    )]
    PeerNotProven {
        /// The peer-identity claim the session's transport declared.
        declared: PeerProof,
    },
    /// The gate ruled: nauthy's typed cause.
    #[error(transparent)]
    Gate(nauthy::Refusal),
    /// The public-path capacity is reached: the node already serves its cap of ADMITTED
    /// public sessions or concurrent public streams. The wire still gets the same payload-free
    /// `Refusal::NotAdmitted` a gate miss gives, so a saturation is indistinguishable from a refusal;
    /// this cause is only the operator's log line. The shared session table is bounded separately by
    /// [`MAX_SESSIONS`](super::exposer::MAX_SESSIONS) and is outside this pool's claim.
    #[error(
        "public capacity reached ({cap}); refusing rather than queueing the admitted public dial"
    )]
    PublicAtCapacity {
        /// Which pool is at its cap (`public sessions` / `public streams`).
        cap: &'static str,
    },
}

/// The wire refusal a host cause becomes. Every cause maps to the same payload-free `NotAdmitted` today,
/// and this function exists so that stays a DECISION rather than a default.
///
/// It is written as an exhaustive match, with the gate's own cause destructured and no wildcard anywhere,
/// because the alternative failed: a new gate outcome added upstream inherits whatever the fall-through
/// happened to be, silently, and a uniform refusal is exactly the kind of answer that must never be
/// inherited. nauthy is about to gain one (an evaluation that ran out of time, which is not a ruling about
/// the dialer at all), and when that pin moves this match will stop compiling until someone rules on it.
/// That is the point, and a reviewer who reaches for a wildcard to make it build has thrown the guard away.
///
/// The uniformity itself is settled and is not what this function reopens: a dialer must not be able to
/// tell a stranger's missing token from a revoked holder's, an absent service from a gated one, or a
/// saturated public pool from a gate miss.
fn wire_refusal(refusal: &HostRefusal) -> Refusal {
    match refusal {
        HostRefusal::MalformedCapability(_)
        | HostRefusal::PeerNotProven { .. }
        | HostRefusal::PublicAtCapacity { .. } => Refusal::NotAdmitted,
        HostRefusal::Gate(gate) => match gate {
            nauthy::Refusal::Missing | nauthy::Refusal::NotGranted | nauthy::Refusal::Revoked => {
                Refusal::NotAdmitted
            }
            // NOT a ruling about the dialer, so not the refusal that says one. The gate ran out of time
            // and decided nothing about their authority; sending the uniform not-admitted answer tells
            // them they lack a credential nothing rejected, and they act on it, stopping their retries
            // and going to look for a token they already hold.
            //
            // INTERIM, and named as one. The ruling on this is that it deserves its own wire code, which
            // is a format change and therefore the founder's call; this is the fallback that same ruling
            // named as acceptable in the meantime, and it changes no format. The cost is that
            // `Unavailable` no longer implies the dialer got past the gate, which is why that variant's
            // own doc was widened rather than left to drift. Taken now because the defect underneath it
            // is live: on the previous pin a valid device badge was refused about one run in three.
            //
            // The detail is FIXED text, never host state. A detail that varied with load would put a
            // channel on a pre-admission refusal, which is the thing the uniform answer exists to deny.
            nauthy::Refusal::Undecided => Refusal::Unavailable {
                detail: RefusalDetail::bounded(
                    "the gate did not finish deciding in time; retry".to_owned(),
                ),
            },
        },
    }
}

impl From<nauthy::Refusal> for HostRefusal {
    fn from(refusal: nauthy::Refusal) -> Self {
        HostRefusal::Gate(refusal)
    }
}

/// An admitted stream: the nauthy witness the dispatch consumes, plus the public-path permit (if any) this
/// stream holds until it ends. The permit rides the binding through the whole of [`serve_request`], so a
/// public stream keeps its slot for exactly its lifetime; a gated stream carries `None` and touches no
/// public capacity.
#[derive(Debug)]
struct AdmittedStream {
    witness: Admitted,
    /// Held for the stream's lifetime; dropped when the binding leaves scope. Never read.
    _stream_permit: Option<OwnedSemaphorePermit>,
}

/// The policy one stream's admission is ruled under: the node base [`Gate`], the two disjoint open
/// overlays (the SAFE `public` and the UNSAFE raw-stream `public_unsafe`), and the public-path capacity
/// pools. Borrowed from the serving context, so [`admit`] reads one handle and a session's permit can
/// never be taken against another node's pools.
#[derive(Clone, Copy)]
struct Admission<'a> {
    gate: &'a Gate,
    public: &'a PublicServices,
    public_unsafe: &'a PublicServices,
    pool: &'a PublicPool,
}

/// Rule on a request under the node's per-service admission: the two disjoint open overlays (`public`, the
/// safe one, and `public_unsafe`, the unsafe raw-stream one) composed with the base family gate, returning
/// the [`Admitted`] witness plus this stream's public permit (if any) on success, or the typed
/// [`HostRefusal`] for the node's OWN logs. A service the operator opened (a member of EITHER overlay)
/// admits any reaching peer under the public caps; every other service faces the base gate and touches no
/// public capacity. The witness is required to reach a service handler, so "authorize before
/// serve" is a compile-time precondition (see [`nauthy::Admitted`]). The refusal returned here NEVER crosses
/// the wire (the caller sends the payload-free `Refusal::NotAdmitted` to a not-admitted dialer); it exists
/// only so the operator can see WHY on their own `tracing` output. Distinguishing missing/not-granted/revoked
/// to the wire would hand an unauthorized peer a revocation and capability-enumeration oracle.
fn admit(
    admission: Admission<'_>,
    session: &PublicSession,
    peer: SessionPeer,
    capability: Option<&str>,
    membership: Option<&str>,
    service: &Service,
) -> Result<AdmittedStream, HostRefusal> {
    let Admission {
        gate: base,
        public,
        public_unsafe,
        pool,
    } = admission;
    // The ONLY branch admission takes on the service NAME is this open-set membership test, and it runs
    // BEFORE any dispatch (the `services.get` in `serve_request` is reached only past this admit). A HIT on
    // EITHER overlay is the sole fast/open path: the service was proven open at `with_public` (safe) or at
    // `Exposer::new` (an unsafe raw stream), so this admits with no cap parse and no crypto, minting the
    // witness through nauthy's OWN `Gate::Open` primitive (tightbeam picks WHICH nauthy primitive per
    // service; it never mints authority itself). Both overlays hold, by construction, exposed served names,
    // so the later dispatch always resolves the name. Testing a second already-public set adds no oracle: a
    // hit on either reveals only the already-public fact that the service admits anyone; a miss on both takes
    // the identical family path below.
    if public.contains(service.as_str()) || public_unsafe.contains(service.as_str()) {
        // An open service needs no badge, so the signet-bound membership slot is irrelevant on this path.
        // The witness is `Origin::Open` with `Admission::Slip`: no token is ruled on and nothing about the
        // peer is verified, so the `ProvenPeer` minted here records the key the peer announced and carries
        // no authority. That is what lets an announced transport keep serving a service the operator opened
        // to anyone, while every gated route (below) refuses.
        let witness = Gate::Open
            .admit_witnessed(
                ProvenPeer::from_handshake(peer.node.verify_key()),
                None,
                service,
            )
            .map_err(HostRefusal::from)?;
        // The ONE place the public caps are taken. A public stream first takes a
        // public-stream permit (held for the stream's life) and then classifies its session (one
        // public-session permit, held until the session closes). Past either cap the answer is a refusal
        // BEFORE any `Response::Ok`, mapped by the caller to the same payload-free `NotAdmitted` a gate
        // miss gives. Stream permit first: a session is only classified by a stream that actually runs, so
        // a refused stream never burns a session slot. A gated route skips this block entirely.
        let stream_permit = Arc::clone(&pool.streams).try_acquire_owned().map_err(|_| {
            HostRefusal::PublicAtCapacity {
                cap: "public streams",
            }
        })?;
        session
            .enter(&pool.sessions)
            .map_err(|_| HostRefusal::PublicAtCapacity {
                cap: "public sessions",
            })?;
        return Ok(AdmittedStream {
            witness,
            _stream_permit: Some(stream_permit),
        });
    }
    // A rooted gate rules on a token BOUND to the dialer's proven key, so it may only run when the
    // transport's declared profile proves the peer: over an announced session a harvested badge is
    // replayable and the binding would vouch for the impersonator. Refuse before minting a `ProvenPeer`
    // or parsing the token. The wire gets the same uniform `NotAdmitted` a gate miss gives; only the
    // node's own log names the declared profile. A genuinely open service was already admitted above,
    // so public traffic over an announced transport is untouched.
    if base.wants_capability() && !peer_proven(peer.security) {
        return Err(HostRefusal::PeerNotProven {
            declared: peer.security.peer,
        });
    }
    // A MISS is EITHER a gated-present name OR a name the node does not serve at all: both take this
    // identical family path (the same cap parse, the same two ed25519 verifies, the same refusal), so a
    // gated service and an absent one are timing- and response-identical. There is no cheaper path for
    // "absent" than for "gated-present", so hit-vs-miss reveals only what is already public (a public name
    // is reachable by anyone), never the gated menu.
    //
    // Parse a presented capability at the edge; a malformed token is a refusal, not a hard error, so the
    // stream ends cleanly rather than being dropped mid-read.
    let cap = match capability.map(Cap::parse).transpose() {
        Ok(cap) => cap,
        Err(error) => return Err(HostRefusal::MalformedCapability(error)),
    };
    // Parse the SECOND slot ONLY when the first is a signet-bound slip: that is the sole path that ANDs a
    // fleet badge, so a plain/bearer/device slip (or none) never triggers the extra `Cap::parse`. The server
    // guards this independently of the dialer (a hostile client ignores the dialer's attach logic), which
    // bounds the second slot's parse work behind the cheap, root-free `is_authority_bound` check. A malformed
    // badge on the signet path is a refusal, not a hard error; both slots inherit `Cap::parse`'s bounds.
    let membership = match cap.as_ref() {
        Some(slip) if slip.is_authority_bound() => match membership.map(Cap::parse).transpose() {
            Ok(membership) => membership,
            Err(error) => return Err(HostRefusal::MalformedCapability(error)),
        },
        _ => None,
    };
    // Mint the peer the transport attested: the declared profile (a completed handshake for `Proven`,
    // exact-by-construction for `InProcess`) is the transport's CLAIM, not a proof this seam re-derives.
    // A rooted gate reaches here only past the predicate above; an open gate needs no peer proof at all.
    let peer = ProvenPeer::from_handshake(peer.node.verify_key());
    // Route the two-cap authority-bound path (a foreign slip AND the membership badge that vouches for the
    // dialer under the slip's foreign authority) through `admit_foreign_witnessed`; every other shape (a
    // membership badge, a plain/bearer/device slip, or no token) is the single-cap path. A `membership` is
    // `Some` only when slot 1 is an authority-bound slip and a badge parsed, so that pairing is the only
    // caller of the foreign twin.
    let witness = match (cap.as_ref(), membership.as_ref()) {
        (Some(slip), Some(badge)) => base
            .admit_foreign_witnessed(peer, slip, badge, service)
            .map_err(HostRefusal::from),
        (presented, _) => base
            .admit_witnessed(peer, presented, service)
            .map_err(HostRefusal::from),
    }?;
    Ok(AdmittedStream {
        witness,
        _stream_permit: None,
    })
}

/// Resolve the requested service against what is exposed: if it names no exposed service but exactly one
/// service is exposed, return that one, so a single-service node needs no named service. Otherwise return
/// the request unchanged (a multi-service node keeps it, to fail later with the "unknown service; this node
/// exposes: …" hint rather than guessing which one was meant).
fn resolve_single_service(requested: Service, services: &HashMap<String, Route>) -> Service {
    if services.contains_key(requested.as_str()) || services.len() != 1 {
        return requested;
    }
    // The sole service's name is already a validated `Service` (parse_services checked it), so this parse
    // cannot fail; fall back to the request if it somehow does rather than unwrap.
    match services.keys().next().map(|only| only.parse::<Service>()) {
        Some(Ok(only)) => only,
        _ => requested,
    }
}

#[cfg(test)]
#[path = "admit_tests.rs"]
mod admit_tests;
