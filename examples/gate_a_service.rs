//! Gate a service behind a capability, then reach it by presenting one, over the bifrost overlay.
//!
//! The companion to [`reach_by_key`](../reach_by_key/index.html): that one admits
//! anyone who reaches the key ([`Gate::Open`](nauthy::Gate::Open)); this one admits only a caller holding a
//! `sheer:` capability the exposer's identity signed. The exposer stands its service behind a *signet gate*
//! (its own key); the owner [`mint_link`](tightbeam::tunnel::mint_link)s a capability granting one service;
//! a connector presents it. No allowlist, no server in the delegation loop: the exposer verifies the signed
//! chain offline.
//!
//! Run it on one machine, no network and no config needed:
//!
//! ```sh
//! cargo run --example gate_a_service
//! ```
//!
//! It uses bifrost's in-process transport so the two nodes talk without touching the network. One wrinkle
//! that transport makes visible: over `MemTransport` the exposer's cap identity and its transport node id
//! are DIFFERENT keys (mem hands out a synthetic id), so the connector dials the mem node id and presents
//! the link with [`Connector::to_node`]. Over a real transport (iroh, quirk) the node binds UNDER the cap
//! secret, so the two coincide and [`Connector::from_link`] both dials and presents from the link alone. The
//! gate logic is identical either way.

use core::time::Duration;
use std::path::PathBuf;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::{Denylist, Identity, Service};
use tightbeam::identity::AsNodeId as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Registry, Services};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// tightbeam's overlay futures are not `Send`, so its tasks run on one thread inside a `LocalSet`.
#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> eyre::Result<()> {
    // 1. A local service to expose, the same tiny TCP echo server as the open example; in real use this is
    //    your ssh daemon, an HTTP origin, a database, anything that speaks over a socket.
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    tokio::task::spawn_local(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::task::spawn_local(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. The exposer's IDENTITY is the root of trust. Its key both binds the overlay node (so it is
    //    reachable) and signs the capabilities the gate honors; a connector needs nothing but a link this
    //    identity signed. (A real node persists this secret; here we pick a fixed one so the example is
    //    self-contained.)
    let identity = Identity::from_secret(&[7u8; 32])?;
    let exposer = Node::new(MemTransport::bind(), NoDiscovery);
    let exposer_key = exposer.node_id();
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);

    // 3. Stand the `ssh` service behind a signet gate rooted at that identity: only a caller presenting a
    //    capability this identity signed (for this service, unexpired) is admitted. `resolve_gate(..)`
    //    is the same policy every embedder applies: not-public means a family gate on the signet, and an
    //    empty denylist admits everything not yet revoked.
    let services = Services::parse(&[format!("ssh={echo_addr}")])?;
    // Nothing is revoked yet, so an empty denylist. A real node loads this from where it persists
    // revocations (`Denylist::load`); the empty set admits everything not yet revoked.
    // `identity.node_id()` is nauthy's `VerifyKey`; `.node_id()` again is the `AsNodeId` bridge to bifrost's
    // `NodeId` (two names for the same ed25519 key on either side of the cap/transport boundary). A real
    // exposer loads this signet from config as a `NodeId` already and never crosses the bridge by hand.
    let signet = identity.node_id().node_id();
    let gate = tunnel::resolve_gate(Some(signet), Denylist::empty(PathBuf::new()))?;
    tokio::task::spawn_local(async move {
        if let Err(e) = Exposer::new(services, Registry::new(), gate)?
            .run(&exposer, CancellationToken::new())
            .await
        {
            eprintln!("exposer stopped: {e}");
        }
        Ok::<_, eyre::Error>(())
    });

    // 4. The owner mints a capability granting exactly `ssh`, valid for an hour. This is offline: it needs
    //    the signing identity but no network. The link IS the grant, a `sheer:<node-id>.<token>` string you
    //    can hand to whoever should reach the service.
    let ssh = "ssh".parse::<Service>()?;
    let link = tunnel::mint_link(&identity, &ssh, Duration::from_secs(3600), false)?;

    // 5. The consumer reaches the service and PRESENTS the link, binding it to a free local port so anything
    //    that connects to that port is tunnelled to the gated echo service on the other node. Over mem it
    //    dials the node id and presents the link (`to_node`); over iroh a bare `Connector::from_link(&link,
    //    ..)` would do both from the link alone (see the module docs).
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = probe.local_addr()?.port();
    drop(probe);
    tokio::task::spawn_local(async move {
        if let Err(e) = async {
            Connector::to_node(exposer_key, ssh.to_string(), Some(link))
                .preflight(&consumer, local_port)
                .await?
                .run()
                .await
        }
        .await
        {
            eprintln!("connector stopped: {e}");
        }
    });

    // 6. Use it. Connect to the local port, retrying until the connector is listening, and echo a message
    //    that travels: local port -> consumer node -> (overlay, gated by capability) -> exposer node ->
    //    echo service, and all the way back. A caller without the link is refused at the gate.
    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", local_port)).await {
            client = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let Some(mut client) = client else {
        eyre::bail!("the connector never started listening (was the capability refused?)");
    };

    let message = b"ping past the gate";
    client.write_all(message).await?;
    let mut echoed = vec![0u8; message.len()];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, message, "the echoed bytes must match what we sent");

    println!(
        "sent {:?}, got {:?} back through the tunnel, admitted by capability alone",
        String::from_utf8_lossy(message),
        String::from_utf8_lossy(&echoed),
    );
    Ok(())
}
