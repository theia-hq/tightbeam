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

/// Expose a local service to peers.
///
/// Authorization is a property of the node, not a per-expose choice: by default a service is gated to this
/// node's signet ANCHOR (set once by `swoosh adopt`), admitting the owner's own devices (membership
/// badges) and anyone they delegate a slip to. The flags are deliberate exceptions to that default, not a
/// menu of policies: `--allow` for a signet-less raw allowlist, `--public` to open a service to anyone,
/// `--trust-root` to trust a signet other than the provisioned one.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=addr` (bare `addr` = `default`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// Admit exactly these keys, no signet needed (the raw allowlist floor). Repeatable. Presence of
    /// `--allow` gates on the list instead of the node's signet anchor.
    #[arg(long = "allow", value_name = "node-id")]
    pub allow: Vec<String>,
    /// Trust this signet instead of the node's provisioned anchor: the foreign-issuer hatch (a runner
    /// trusting YOUR key without ever holding your secret, so a compromised runner can mint no access).
    #[arg(long, value_name = "node-id")]
    pub trust_root: Option<NodeId>,
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
    /// `anchor` is this node's provisioned signet: the [`NodeId`] it trusts, or `None` if it was never
    /// provisioned. The default gate verifies presented tokens against it; the flags override it.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        anchor: Option<NodeId>,
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
        let gate = Arc::new(self.gate(anchor).await?);
        // The readiness banner names the node id AND the effective gate, so "who can reach this right now?"
        // is answerable at a glance. `--quiet` withholds it so a key never lands in an unattended log.
        if !self.quiet {
            println!("tightbeam ready. peers can reach these services at:\n");
            println!(
                "    {}                     (share this key, or mint a link with `tightbeam share`)\n",
                node.node_id()
            );
            let mut names: Vec<&str> = services.keys().map(String::as_str).collect();
            names.sort_unstable();
            println!(
                "exposing {} \u{2014} gate: {}. press ctrl-c to stop.",
                names.join(", "),
                self.gate_description(anchor)
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

    /// Build the authorization gate. Not a policy menu: the default is the node's signet anchor, and the
    /// flags are exceptions. `--public` opens the door to anyone; `--allow` names a raw allowlist;
    /// otherwise the gate is the signet (an explicit `--trust-root`, else the provisioned anchor), which
    /// fails LOUDLY if neither is set rather than falling back to anything permissive.
    async fn gate(&self, anchor: Option<NodeId>) -> eyre::Result<Gate> {
        if self.public {
            return Ok(Gate::Open);
        }
        if !self.allow.is_empty() {
            return Ok(Gate::Strict(parse_allowed(&self.allow)?));
        }
        let root = self.trust_root.or(anchor).ok_or_else(|| {
            eyre::eyre!(
                "this node has no signet to gate on: provision it with `swoosh adopt <authkey>`, \
                 or pass --trust-root <signet>, --allow <key>, or --public"
            )
        })?;
        // The revocation denylist is loaded once here; a `tightbeam revoke` adds to the file, which the
        // next exposer run reads. Offline, no server.
        let denylist = Denylist::load(crate::config::revoked_path()?).await?;
        Ok(Gate::Family(root, Box::new(denylist)))
    }

    /// A one-line description of the effective gate, for the readiness banner: trust made visible.
    fn gate_description(&self, anchor: Option<NodeId>) -> String {
        if self.public {
            "public (anyone, unauthenticated)".to_owned()
        } else if !self.allow.is_empty() {
            format!("allowlist ({} key(s))", self.allow.len())
        } else {
            match self.trust_root.or(anchor) {
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
                // keyless shell can never be reached un-gated.
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
            Refusal::NotPermitted => "not permitted".to_owned(),
            Refusal::Revoked => "capability has been revoked".to_owned(),
        })
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
        services.insert(name, addr);
    }
    Ok(services)
}

/// Parse node ids into an allowlist set.
fn parse_allowed(ids: &[String]) -> eyre::Result<std::collections::HashSet<NodeId>> {
    ids.iter()
        .map(|id| id.parse::<NodeId>().map_err(Into::into))
        .collect()
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
