// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The membership badge, end to end over the in-process transport: a device presenting a badge its signet
//! signed — a cap carrying a `member(true)` fact in its authority block — reaches ANY service on a
//! family-gated node, with no per-service slip. And a badge BOUND to one device (`mint_member`) is
//! refused when a different device presents it, so a leaked badge is useless off its key.
//!
//! The family gate rules on the presented token AND the proven dialer: `admit_family` injects the peer the
//! transport proved as a `bound_device` fact, and a bound badge grants only when that fact matches its
//! binding. Over `mem` the proven peer is the transport's synthetic node id, independent of the signet's
//! cap key — which is exactly what lets this test bind a badge to the connector's proven id and exercise
//! the binding check without a keyed transport. Over iroh/quirk the two coincide (the node binds under the
//! signet secret), so the same badge both proves membership and matches its own binding.

use core::time::Duration;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::Identity;
use tightbeam::connect::Target;
use tightbeam::{ConnectCmd, ExposeCmd};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The signet's fixed secret. Its ed25519 public half is the anchor the family gate trusts, and it roots
/// every badge minted here.
const SIGNET_SECRET: [u8; 32] = [42u8; 32];

#[tokio::test]
async fn family_gate_admits_a_bound_membership_badge_and_refuses_a_foreign_binding() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let echo_addr = spawn_echo().await;
            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();

            // Expose `web=<echo>` behind the DEFAULT family gate, anchored to the signet. No `--allow`:
            // admission is by membership alone. The service is `web`, NOT the badge's service, to prove a
            // membership badge is whole-node (any service), not a per-service slip.
            let anchor = Identity::from_secret(&SIGNET_SECRET).unwrap().node_id();
            tokio::task::spawn_local(async move {
                ExposeCmd {
                    services: vec![format!("web={echo_addr}")],
                    public: false,
                    quiet: false,
                }
                .run(&exposer, [0u8; 32], Some(anchor))
                .await
                .unwrap();
            });

            let signet = Identity::from_secret(&SIGNET_SECRET).unwrap();

            // The owner's device: a consumer node whose PROVEN id the signet binds the badge to. The badge
            // grants membership (whole-node), bound to this device — the `swoosh mint` shape.
            let device = Node::new(MemTransport::bind(), NoDiscovery);
            let device_badge = signet
                .mint_member(device.node_id(), nauthy::expires_in(Duration::from_secs(3600)))
                .unwrap()
                .link()
                .unwrap();

            // The bound device presents its badge and reaches `web`, though the badge names no service:
            // membership is whole-node admission. This is `swoosh ssh ci` working by MEMBERSHIP.
            let echoed = connect_and_echo(device, exposer_id, "web", Some(&device_badge)).await;
            assert_eq!(
                echoed.as_deref(),
                Some(&b"i am a member"[..]),
                "a bound membership badge admits its device to any service"
            );

            // A badge bound to a DIFFERENT device, presented by this one: the proven dialer does not match
            // the binding, so the family gate refuses it. A leaked badge is useless off its key.
            let other_device_id = Node::new(MemTransport::bind(), NoDiscovery).node_id();
            let foreign_badge = signet
                .mint_member(other_device_id, nauthy::expires_in(Duration::from_secs(3600)))
                .unwrap()
                .link()
                .unwrap();
            let impostor = Node::new(MemTransport::bind(), NoDiscovery);
            let refused = connect_and_echo(impostor, exposer_id, "web", Some(&foreign_badge)).await;
            assert_eq!(
                refused, None,
                "a badge bound to another device must be refused when a different device presents it"
            );
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

/// Run a `connect` from `consumer` against the exposer presenting a badge, send a probe, and return the
/// echo if the tunnel carried it within a short window (a refused connection never echoes). The consumer
/// node is passed in so its PROVEN id can be bound into the badge before the dial.
async fn connect_and_echo(
    consumer: Node<MemTransport, NoDiscovery>,
    exposer: bifrost::NodeId,
    service: &str,
    badge: Option<&str>,
) -> Option<Vec<u8>> {
    let port = free_port().await;
    let service = service.to_owned();
    let present = badge.map(str::to_owned);
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

    let probe = b"i am a member";
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
