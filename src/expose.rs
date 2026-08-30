//! `tightbeam expose`: publish local services under this node's key and forward inbound streams.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Admitted, Cap, Denylist, Gate, Refusal, Service};
use tokio::io;
use tokio::net::TcpStream;

use crate::protocol::{Request, Response};
use crate::splice;

/// How long to wait for a connector to send its opening request before dropping the stream. Bounds the
/// pre-gate work an unauthenticated peer can pin (a slow-loris that opens a stream and never speaks).
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The maximum number of peer sessions served concurrently. Past this, `accept` stops being polled so new
/// connections queue at the transport (backpressure), bounding the memory a flood of peers can pin.
const MAX_SESSIONS: usize = 256;

/// The maximum number of in-flight streams per session, bounding what a single connected peer can pin.
const MAX_STREAMS_PER_SESSION: usize = 256;

/// How the readiness banner names the tool exposing the services, so the same code serves both callers
/// without hardcoding one binary. `tightbeam expose` says "tightbeam ... `tightbeam share`"; `swoosh
/// tunnel expose` says "swoosh tunnel ... `swoosh grant issue`". Two `&str`s, not one, because the
/// ready-name and the mint-verb differ (`swoosh tunnel` vs `swoosh grant issue`).
pub struct Brand {
    /// The name that leads the readiness banner, e.g. `tightbeam` or `swoosh tunnel`.
    pub ready: &'static str,
    /// The exact command that mints a link for this node, e.g. `tightbeam share` or `swoosh grant issue`.
    pub share: &'static str,
}

impl Brand {
    /// The banner for `tightbeam` invoked directly.
    pub const TIGHTBEAM: Self = Self {
        ready: "tightbeam",
        share: "tightbeam share",
    };
}

/// Expose a local service to peers.
///
/// Authorization is a property of the node, not a per-expose choice: by default a service is gated to this
/// node's signet (set once by `swoosh adopt`), admitting the owner's own devices (membership badges) and
/// anyone they delegate a slip to. `--public` is the one deliberate exception: it opens a service to
/// anyone, unauthenticated.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=addr` (bare `addr` = `default`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// Expose to ANYONE, unauthenticated: the one deliberate opt-out from the signet. Refused for a shell
    /// service (`sshd:`), which has no auth of its own.
    #[arg(long)]
    pub public: bool,
    /// Suppress the readiness banner (the node id, services, and gate). For unattended/CI use where the
    /// key must never land in a log; the tunnel still runs.
    #[arg(long)]
    pub quiet: bool,
}

impl ExposeCmd {
    /// Accept overlay sessions from permitted peers and forward each inbound stream to the service.
    ///
    /// `signet` is this node's provisioned signet: the [`NodeId`] it trusts, or `None` if it was never
    /// provisioned. The default gate verifies presented tokens against it; `--public` overrides it.
    /// `brand` names the calling tool in the readiness banner, so it points at the right binary's `share`.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
        brand: Brand,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let services = Arc::new(parse_services(&self.services)?);
        // A shell service has no auth of its own, so the gate IS its authentication: refuse to open one to
        // the world, which would hand a keyless shell to anyone who reaches this node.
        if self.public && services.values().any(|addr| addr == "sshd:") {
            eyre::bail!(
                "a shell service (sshd:) has no auth of its own and must be gated; \
                 drop --public, which would expose an unauthenticated shell to anyone"
            );
        }
        // Build the gate before announcing readiness: an unprovisioned node with no explicit override
        // fails HERE, loudly, rather than ever serving on a permissive default.
        let gate = Arc::new(self.gate(signet).await?);
        // The readiness banner names the node id AND the effective gate, so "who can reach this right now?"
        // is answerable at a glance. `--quiet` withholds it so a key never lands in an unattended log.
        if !self.quiet {
            println!(
                "{} ready. peers can reach these services at:\n",
                brand.ready
            );
            println!(
                "    {}                     (share this key, or mint a link with `{}`)\n",
                node.node_id(),
                brand.share
            );
            let mut names: Vec<&str> = services.keys().map(String::as_str).collect();
            names.sort_unstable();
            println!(
                "exposing {}. gate: {}. ctrl-c to stop.",
                names.join(", "),
                self.gate_description(signet)
            );
        }
        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                // Cap concurrent sessions: past the cap, stop polling `accept` so new connections queue at
                // the transport (backpressure) rather than each pinning a task set, bounding a peer flood.
                accepted = node.accept(), if sessions.len() < MAX_SESSIONS => {
                    // The listener outlives any one peer: a transient accept error must not tear down
                    // the sessions already being served, so log it and keep accepting.
                    let session = match accepted {
                        Ok(session) => session,
                        Err(error) => {
                            tracing::warn!(%error, "accept failed; still listening");
                            continue;
                        }
                    };
                    sessions.push(serve_session(
                        session,
                        Arc::clone(&gate),
                        Arc::clone(&services),
                        host_seed,
                    ));
                }
                Some(result) = sessions.next(), if !sessions.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "session ended");
                    }
                }
            }
        }
    }

    /// Build the authorization gate. Two modes, no policy menu: the default gates on the node's signet
    /// (admitting its members and delegates), and `--public` is the one deliberate opt-out to anyone.
    /// Unprovisioned + not public fails LOUDLY rather than falling back to anything permissive.
    async fn gate(&self, signet: Option<NodeId>) -> eyre::Result<Gate> {
        if self.public {
            return Ok(Gate::Open);
        }
        let root = signet.ok_or_else(|| {
            eyre::eyre!(
                "this node has no signet to gate on: provision it with `swoosh adopt <authkey>`, \
                 or pass --public to expose to anyone"
            )
        })?;
        // The revocation denylist is loaded once here; a `tightbeam revoke` adds to the file, which the
        // next exposer run reads. Offline, no server.
        let denylist = Denylist::load(crate::config::revoked_path()?).await?;
        Ok(Gate::Family(root, Box::new(denylist)))
    }

    /// A one-line description of the effective gate, for the readiness banner: trust made visible.
    fn gate_description(&self, signet: Option<NodeId>) -> String {
        if self.public {
            "public (anyone, unauthenticated)".to_owned()
        } else {
            match signet {
                Some(root) => format!("signet {}", root.short()),
                None => "unprovisioned".to_owned(),
            }
        }
    }
}

/// Serve one accepted session: handle each inbound stream's service request under the gate.
async fn serve_session<S: Session>(
    session: S,
    gate: Arc<Gate>,
    services: Arc<HashMap<String, String>>,
    host_seed: [u8; 32],
) -> eyre::Result<()>
where
    S::Write: Send + 'static,
    S::Read: Send + 'static,
{
    let peer = session.peer();
    let mut pipes = FuturesUnordered::new();
    // Stop accepting new streams once `accept_bi` errors (the session is closing): drain the in-flight
    // pipes rather than reaping them with `?`, the same courtesy `connect` gives its local listener.
    let mut accepting = true;
    loop {
        tokio::select! {
            // Cap in-flight streams per session: past the cap, stop polling `accept_bi` so the peer's
            // further streams queue at the transport (backpressure) instead of each pinning a task and a
            // buffer. A single peer cannot exhaust the node with unbounded concurrent streams.
            accepted = session.accept_bi(), if accepting && pipes.len() < MAX_STREAMS_PER_SESSION => {
                match accepted {
                    Ok((writer, reader)) => pipes.push(serve_request(
                        peer,
                        writer,
                        reader,
                        Arc::clone(&gate),
                        Arc::clone(&services),
                        host_seed,
                    )),
                    Err(error) => {
                        tracing::warn!(%peer, %error, "accept_bi failed; draining in-flight streams");
                        accepting = false;
                    }
                }
            }
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "pipe ended");
                }
            }
            // No more streams to accept and none in flight: the session is done.
            else => break,
        }
    }
    Ok(())
}

/// Serve one inbound stream: read the request, apply the gate, reply, and pipe on success.
///
/// The gate decides per stream, not per session, because the requested service (and any presented
/// capability) is a property of the stream: one session may carry several service requests, each gated on
/// its own merits.
#[cfg_attr(not(feature = "ssh"), allow(unused_variables))]
async fn serve_request<W, R>(
    peer: NodeId,
    mut writer: W,
    mut reader: R,
    gate: Arc<Gate>,
    services: Arc<HashMap<String, String>>,
    host_seed: [u8; 32],
) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin + Send + 'static,
    R: io::AsyncRead + Unpin + Send + 'static,
{
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
    let Ok(service) = request.service.parse::<Service>() else {
        let message = format!("invalid service name {:?}", request.service);
        return Response::Error(message)
            .write(&mut writer)
            .await
            .map_err(Into::into);
    };
    // A node exposing exactly one service should not require `--service`: if the request names no exposed
    // service (a connector defaulting to `default`) and there is only one, resolve to it. Done BEFORE the
    // gate so a delegated slip for that service still matches (the gate checks the RESOLVED service).
    let service = resolve_single_service(service, &services);

    let admitted = match admit(&gate, peer, request.capability.as_deref(), &service) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            tracing::warn!(%peer, service = %service, %refusal, "refused");
            return Response::Error(refusal)
                .write(&mut writer)
                .await
                .map_err(Into::into);
        }
    };

    match services.get(service.as_str()) {
        // `fetch:` is the HTTP egress target: rather than splice to a fixed local socket, the node acts
        // as an HTTP client and streams an origin response back (see `crate::fetch`).
        Some(addr) if addr == "fetch:" => {
            Response::Ok.write(&mut writer).await?;
            crate::fetch::serve_fetch(&mut writer, &mut reader).await?;
        }
        // `sshd:` is a keyless SSH server (the `sshh` crate): the cap gate already authorized the peer, so
        // the ssh server accepts auth `none`. A standard `ssh`/`scp` client reaches a shell with no ssh
        // keys, the way Tailscale SSH is keyless behind WireGuard. Built only with `--features ssh`, so the
        // heavy russh/pty dependency tree stays out of the default tunnel binary.
        Some(addr) if addr == "sshd:" => {
            #[cfg(feature = "ssh")]
            {
                Response::Ok.write(&mut writer).await?;
                // The gate admitted this peer; the `Admitted` witness proves it at the type level, so a
                // keyless shell can never be reached un-gated. The witness binds no peer itself, so this
                // guarantee holds only because the admit (above) and this serve share one stream frame:
                // never hoist the admit to session scope, or one witness would cover streams the gate
                // never ruled on.
                sshh::serve(&admitted, host_seed, writer, reader).await?;
            }
            #[cfg(not(feature = "ssh"))]
            Response::Error(
                "ssh support not built in; rebuild tightbeam with --features ssh".to_owned(),
            )
            .write(&mut writer)
            .await?;
        }
        Some(addr) => {
            Response::Ok.write(&mut writer).await?;
            dial_and_splice(addr, writer, reader).await?;
        }
        None => {
            // Name what this node DOES expose, so a service-name mismatch (the connector defaulting to
            // `default` while the exposer named `web`) reads as a fixable error, not an opaque reset.
            let mut available: Vec<&str> = services.keys().map(String::as_str).collect();
            available.sort_unstable();
            let message = format!(
                "unknown service {:?}; this node exposes: {}",
                service.as_str(),
                available.join(", ")
            );
            Response::Error(message).write(&mut writer).await?;
        }
    }
    Ok(())
}

/// Apply the gate to a request, returning the [`Admitted`] witness on success or a peer-facing refusal
/// string. The witness is required to reach a service handler, so "authorize before serve" is a
/// compile-time precondition (see [`nauthy::Admitted`]).
fn admit(
    gate: &Gate,
    peer: NodeId,
    capability: Option<&str>,
    service: &Service,
) -> Result<Admitted, String> {
    // Parse a presented capability at the edge; a malformed token is a refusal, not a hard error, so the
    // connector gets a clean "not permitted" rather than a dropped stream.
    let cap = match capability.map(Cap::parse).transpose() {
        Ok(cap) => cap,
        Err(_) => return Err("malformed capability".to_owned()),
    };
    gate.admit_witnessed(peer, cap.as_ref(), service)
        .map_err(|refusal| match refusal {
            Refusal::Missing => "this service requires a capability".to_owned(),
            Refusal::NotGranted => "capability does not grant this service".to_owned(),
            Refusal::Revoked => "capability has been revoked".to_owned(),
        })
}

/// Resolve the requested service against what is exposed: if it names no exposed service but exactly one
/// service is exposed, return that one, so a single-service node needs no `--service`. Otherwise return
/// the request unchanged (a multi-service node keeps it, to fail later with the "unknown service; this node
/// exposes: …" hint rather than guessing which one was meant).
fn resolve_single_service(requested: Service, services: &HashMap<String, String>) -> Service {
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

/// Parse `name=addr` service entries; a bare `addr` becomes the `default` service.
fn parse_services(entries: &[String]) -> eyre::Result<HashMap<String, String>> {
    let mut services = HashMap::new();
    for entry in entries {
        let (name, addr) = match entry.split_once('=') {
            Some((name, addr)) => (name.to_owned(), addr.to_owned()),
            None => ("default".to_owned(), String::clone(entry)),
        };
        // Validate the name through the same domain type the wire uses, so an exposed name and a
        // requested name are compared as the same kind of thing.
        name.parse::<Service>()?;
        // Validate the ADDR too: without this, `expose web` silently maps the `default` service to the
        // literal address "web", which only fails at dial time as an opaque reset. Fail HERE instead.
        validate_addr(&addr, entry)?;
        services.insert(name, addr);
    }
    Ok(services)
}

/// Reject an addr that is not a real forwarding target, so a bare service name (`expose web`) fails at
/// parse with a teaching message instead of silently pointing the `default` service at an undialable
/// host. Valid targets: `sshd:` (keyless shell), `fetch:` (HTTP egress), `unix:<path>`, or a `host:port`.
fn validate_addr(addr: &str, entry: &str) -> eyre::Result<()> {
    let is_host_port = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    if addr == "sshd:" || addr == "fetch:" || addr.starts_with("unix:") || is_host_port {
        return Ok(());
    }
    // A bare token with no `=` was almost certainly meant as a service NAME, not an address.
    if !entry.contains('=') {
        eyre::bail!(
            "`{entry}` is not an address to forward to. Did you mean a service pointing at one, e.g. \
             `{entry}=127.0.0.1:8080`? (an address is host:port, unix:<path>, sshd:, or fetch:)"
        );
    }
    eyre::bail!(
        "`{addr}` is not a valid forwarding address (host:port, unix:<path>, sshd:, or fetch:)"
    )
}

/// Dial a service target (a `unix:<path>` socket or a `host:port`) and pipe it to the bifrost stream.
async fn dial_and_splice<W, R>(addr: &str, writer: W, reader: R) -> eyre::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    if let Some(path) = addr.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            let local = tokio::net::UnixStream::connect(path).await?;
            splice(local, writer, reader).await?;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            eyre::bail!("unix sockets are not supported on this platform");
        }
    } else {
        let local = TcpStream::connect(addr).await?;
        splice(local, writer, reader).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nauthy::Service;

    use super::{parse_services, resolve_single_service};

    #[test]
    fn a_single_service_node_needs_no_service_name() {
        let svc =
            |n: &str| -> Service { n.parse().unwrap_or_else(|_| panic!("valid service: {n}")) };
        let one: HashMap<String, String> = [("web".to_owned(), "127.0.0.1:80".to_owned())].into();
        // A connector defaulting to `default` on a single-service node resolves to that one service.
        assert_eq!(resolve_single_service(svc("default"), &one).as_str(), "web");
        // A request that already names the exposed service is unchanged.
        assert_eq!(resolve_single_service(svc("web"), &one).as_str(), "web");

        let two: HashMap<String, String> = [
            ("web".to_owned(), "127.0.0.1:80".to_owned()),
            ("ssh".to_owned(), "sshd:".to_owned()),
        ]
        .into();
        // With two services, an unmatched request is left as-is (fails later with the hint, never guesses).
        assert_eq!(
            resolve_single_service(svc("default"), &two).as_str(),
            "default"
        );
    }

    #[test]
    fn a_bare_service_name_is_rejected_with_a_hint() {
        // `expose web` was silently mapped to the `default` service at addr "web"; now it fails at parse.
        let Err(err) = parse_services(&["web".to_owned()]) else {
            panic!("bare `web` should be rejected, not treated as addr \"web\"");
        };
        assert!(
            err.to_string().contains("web=127.0.0.1:8080"),
            "the error should teach the grammar: {err}"
        );
    }

    #[test]
    fn real_targets_parse() {
        for entry in [
            "web=127.0.0.1:8080",
            "ssh=sshd:",
            "proxy=fetch:",
            "db=unix:/run/db.sock",
            "127.0.0.1:5000",
        ] {
            assert!(
                parse_services(&[entry.to_owned()]).is_ok(),
                "{entry} should parse"
            );
        }
    }

    #[test]
    fn a_named_service_pointed_at_a_bogus_addr_is_rejected() {
        assert!(parse_services(&["web=nonsense".to_owned()]).is_err());
    }
}
