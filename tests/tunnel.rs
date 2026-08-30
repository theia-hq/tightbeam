use core::time::Duration;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use tightbeam::connect::Target;
use tightbeam::{ConnectCmd, ExposeCmd};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A TCP client reaches a local echo service through a tightbeam tunnel across two bifrost nodes.
#[tokio::test]
async fn tunnels_tcp_over_bifrost() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // A local echo service that the exposer forwards to.
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_addr = echo.local_addr().unwrap();
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

            // A free local port for the consumer to listen on.
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_port = probe.local_addr().unwrap().port();
            drop(probe);

            // Exposer and consumer nodes over the in-process mem transport (self-discovering).
            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);

            // A public gate needs no identity or signet: any peer reaching the key is served (this test
            // exercises the tunnel path, not authorization).
            tokio::task::spawn_local(async move {
                ExposeCmd {
                    services: vec![echo_addr.to_string()],
                    public: true,
                    quiet: false,
                }
                .run(&exposer, [0u8; 32], None)
                .await
                .unwrap();
            });
            tokio::task::spawn_local(async move {
                ConnectCmd {
                    target: Target::Node(exposer_id),
                    to: Some(local_port),
                    stdio: false,
                    service: "default".to_string(),
                    present: None,
                }
                .run(&consumer)
                .await
                .unwrap();
            });

            // Reach the echo service through the tunnel, retrying until the consumer is listening.
            let mut client = None;
            for _ in 0..100 {
                if let Ok(stream) = TcpStream::connect(("127.0.0.1", local_port)).await {
                    client = Some(stream);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut client = client.expect("consumer never started listening");

            let message = b"ping over the overlay";
            client.write_all(message).await.unwrap();
            let mut echoed = vec![0u8; message.len()];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, message);
        })
        .await;
}
