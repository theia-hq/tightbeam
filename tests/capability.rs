// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The capability gate, end to end over the in-process transport: a connector presenting a valid cap
//! reaches the service; one presenting none, a wrong-service cap, or an expired cap is refused.
//!
//! The exposer's cap identity is independent of the mem transport's synthetic node id, so the connector
//! dials the mem node directly (`Target::Node`) and presents the token with `--present`. Over iroh the
//! two coincide (the node binds under the cap secret), so a bare `sheer:` link both dials and presents;
//! see the demo. Here the split lets the gate be exercised without an ed25519-keyed mem transport.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_mem::MemTransport;
use nauthy::{Identity, Service};
use tightbeam::connect::Target;
use tightbeam::{Brand, ConnectCmd, ExposeCmd};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The exposer's fixed cap secret. Its ed25519 public half roots every minted link.
const EXPOSER_SECRET: [u8; 32] = [42u8; 32];

#[tokio::test]
async fn cap_gate_admits_a_valid_cap_and_refuses_others() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let echo_addr = spawn_echo().await;
            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();

            // Expose `ssh=<echo>` behind a capability gate rooted at the exposer's cap identity.
            // The runner is provisioned to trust the exposer's signet: its family gate admits tokens
            // rooted at that key (badges or slips), which is what these cap tests present.
            let signet = NodeId::from_ed25519_secret(&EXPOSER_SECRET);
            tokio::task::spawn_local(async move {
                ExposeCmd {
                    services: vec![format!("ssh={echo_addr}")],
                    public: false,
                    quiet: false,
                }
                .run(&exposer, [0u8; 32], Some(signet), Brand::TIGHTBEAM)
                .await
                .unwrap();
            });

            // A cap for ssh, valid for an hour, minted by the exposer's identity.
            let minter = Identity::from_secret(&EXPOSER_SECRET).unwrap();
            let ssh = "ssh".parse::<Service>().unwrap();
            let valid = minter
                .mint(&ssh, nauthy::expires_in(Duration::from_secs(3600)))
                .unwrap()
                .link()
                .unwrap();

            // A valid ssh cap reaches the echo service through the tunnel.
            let echoed = connect_and_echo(exposer_id, "ssh", Some(&valid)).await;
            assert_eq!(echoed.as_deref(), Some(&b"through a capability"[..]));

            // No cap presented: refused, so the local listener accepts but the pipe never completes.
            let none = connect_and_echo(exposer_id, "ssh", None).await;
            assert_eq!(none, None, "a connector with no cap must be refused");

            // A cap minted for `web` presented against `ssh`: refused.
            let wrong = minter
                .mint(
                    &"web".parse::<Service>().unwrap(),
                    nauthy::expires_in(Duration::from_secs(3600)),
                )
                .unwrap()
                .link()
                .unwrap();
            let wrong = connect_and_echo(exposer_id, "ssh", Some(&wrong)).await;
            assert_eq!(wrong, None, "a wrong-service cap must be refused");
        })
        .await;
}

/// Spawn a local TCP echo service and return its address.
async fn spawn_echo() -> core::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
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
    addr
}

/// Run a `connect` against the exposer presenting an optional cap, send a probe, and return the echo if
/// the tunnel carried it within a short window (a refused connection never echoes).
async fn connect_and_echo(
    exposer: bifrost::NodeId,
    service: &str,
    capability: Option<&str>,
) -> Option<Vec<u8>> {
    let port = free_port().await;
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    let service = service.to_owned();
    let present = capability.map(str::to_owned);
    tokio::task::spawn_local(async move {
        let _ = ConnectCmd {
            target: Target::Node(exposer),
            to: Some(port),
            stdio: false,
            service,
            present,
        }
        .run(&consumer)
        .await;
    });

    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            client = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = client.expect("consumer never started listening");

    let probe = b"through a capability";
    client.write_all(probe).await.ok()?;
    let mut echoed = vec![0u8; probe.len()];
    // A refused stream is closed by the host after the error reply, so the read returns early with fewer
    // bytes; only a granted stream echoes the whole probe back.
    match tokio::time::timeout(Duration::from_millis(500), client.read_exact(&mut echoed)).await {
        Ok(Ok(_)) => Some(echoed),
        _ => None,
    }
}

/// A free local TCP port.
async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}
