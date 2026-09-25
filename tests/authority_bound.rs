// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The authority-bound slip, end to end over the in-process transport: work issues ONE slip for a service,
//! bound to a hire's authority `X` (their root). A hire DEVICE reaches work presenting BOTH the
//! slip (slot 1) AND its own membership badge under `X` (slot 2). The gate admits iff the slip is valid at
//! work's own root AND the presenter's proven device is a member of `X` (its badge verifies under `X`, bound
//! to the proven device). Any one alone fails, and a badge under the WRONG authority fails.
//!
//! Over `mem` the proven peer is the transport's synthetic node id, independent of either root's cap key,
//! which is exactly what lets this test bind the member badge to the connector's proven id and exercise the
//! device binding without a keyed transport.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_mem::MemTransport;
use nauthy::{FileDenylist, Identity, Link, Service};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Router};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Work's root secret: its ed25519 public half is the ONE root the family gate trusts, and the root the
/// authority-bound slip is issued under.
const WORK_SECRET: [u8; 32] = [7u8; 32];
/// The hire's root secret `X`: it signs the hire's device badges. Work never holds it; work only
/// NAMES its public half in the slip.
const HIRE_SECRET: [u8; 32] = [2u8; 32];
/// A third, unrelated authority `Y`: a badge under it must never satisfy a slip bound to `X`.
const OTHER_SECRET: [u8; 32] = [3u8; 32];

#[tokio::test]
async fn an_authority_bound_slip_admits_a_hire_device_that_proves_membership() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let echo_addr = spawn_echo().await;
            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();

            // Work exposes `web=<echo>` behind the DEFAULT family gate, rooted at WORK's key: the one and
            // only anchor. The hire's authority `X` rides transitively inside a slip work signed, never as a
            // second trusted root.
            let work_root = NodeId::from_ed25519_secret(&WORK_SECRET);
            tokio::task::spawn_local(async move {
                let gate = tunnel::resolve_gate(Some(work_root), empty_denylist().await).unwrap();
                Router::new(gate)
                    .parse(&[format!("web=tcp:{echo_addr}")])
                    .unwrap()
                    .expose()
                    .unwrap()
                    .run(&exposer, CancellationToken::new())
                    .await
                    .unwrap();
            });

            let work = Identity::from_secret(&WORK_SECRET).unwrap();
            let hire = Identity::from_secret(&HIRE_SECRET).unwrap();
            let web: Service = "web".parse().unwrap();

            // The slip work issues to the hire's authority `X`: valid at WORK's root, naming `X` as the
            // authority whose members may use it. Inert alone (it admits no one without a member badge).
            let slip = Link::mint_authority_bound(
                &work,
                &web,
                Identity::from_secret(&HIRE_SECRET).unwrap().verifying_key(),
                Duration::from_secs(3600),
            )
            .unwrap();

            // (a) ADMIT: the hire device presents the slip (slot 1) AND its own badge under `X` bound to the
            // proven dialer (slot 2). Both leaves hold, so the two-token AND admits and the tunnel echoes.
            let device = Node::new(MemTransport::bind(), NoDiscovery);
            let member_badge = hire
                .mint_member(
                    device.node_id().verify_key().expect("a checked key"),
                    nauthy::Request::expires_in(Duration::from_secs(3600)),
                )
                .unwrap()
                .link()
                .unwrap();
            let echoed = connect_and_echo(
                device,
                exposer_id,
                "web",
                slip.as_str(),
                Some(member_badge.as_str()),
            )
            .await;
            assert_eq!(
                echoed.as_deref(),
                Some(&b"a hire reaching work"[..]),
                "slip + a valid member badge under X, bound to the proven device, admits"
            );

            // (b) SLIP ALONE: drop slot 2. The slip is inert on its own and the authority-bound arm has
            // no badge to verify, so the gate refuses and the port never binds.
            let no_badge = Node::new(MemTransport::bind(), NoDiscovery);
            let refused = connect_and_echo(no_badge, exposer_id, "web", slip.as_str(), None).await;
            assert_eq!(refused, None, "the slip alone (no member badge) is refused");

            // (c) WRONG AUTHORITY: present a badge under `Y`, a root the slip does NOT name. Its root does not
            // match the `X` the slip pins, so the badge fails and the AND cannot hold.
            let other = Identity::from_secret(&OTHER_SECRET).unwrap();
            let stray = Node::new(MemTransport::bind(), NoDiscovery);
            let wrong_badge = other
                .mint_member(
                    stray.node_id().verify_key().expect("a checked key"),
                    nauthy::Request::expires_in(Duration::from_secs(3600)),
                )
                .unwrap()
                .link()
                .unwrap();
            let refused = connect_and_echo(
                stray,
                exposer_id,
                "web",
                slip.as_str(),
                Some(wrong_badge.as_str()),
            )
            .await;
            assert_eq!(
                refused, None,
                "a badge under the wrong authority Y is refused"
            );
        })
        .await;
}

/// Run a `connect` from `consumer` presenting the authority-bound `slip` in slot 1 and an optional member
/// `badge` in slot 2, send a probe, and return the echo if the tunnel carried it within a short window (a
/// refused connection never echoes). The consumer node is passed in so its PROVEN id can be bound into the
/// badge before the dial.
async fn connect_and_echo(
    consumer: Node<MemTransport, NoDiscovery>,
    exposer: NodeId,
    service: &str,
    slip: &str,
    badge: Option<&str>,
) -> Option<Vec<u8>> {
    let port = free_port().await;
    let service = service.parse::<Service>().unwrap();
    let slip = slip.parse::<Link>().unwrap();
    let badge = badge.map(|text| text.parse::<Link>().unwrap());
    tokio::task::spawn_local(async move {
        let mut connector = Connector::to_node(exposer, service, Some(slip));
        if let Some(badge) = badge {
            connector = connector.with_membership(badge);
        }
        // A refused connector fails at `preflight` (before the port binds), so the client below never
        // connects and the helper returns `None`; an admitted one binds and forwards.
        if let Ok(forward) = connector.preflight(&consumer, port).await {
            let _ = forward.run().await;
        }
    });

    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            client = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = client?;

    let probe = b"a hire reaching work";
    client.write_all(probe).await.ok()?;
    let mut echoed = vec![0u8; probe.len()];
    match tokio::time::timeout(Duration::from_millis(500), client.read_exact(&mut echoed)).await {
        Ok(Ok(_)) => Some(echoed),
        _ => None,
    }
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

/// A free local TCP port.
async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

/// An empty revocation denylist (an absent file is an empty set); this test exercises admission, not
/// revocation.
async fn empty_denylist() -> FileDenylist {
    let path = std::env::temp_dir().join(format!(
        "tightbeam-authority-bound-denylist-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    FileDenylist::load(path).await.unwrap()
}
