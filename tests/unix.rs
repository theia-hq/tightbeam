#![cfg(unix)]

use core::time::Duration;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use tightbeam::connect::Target;
use tightbeam::{Brand, ConnectCmd, ExposeCmd};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UnixListener};

/// A `unix:` service target is reached through the tunnel via a local TCP port.
#[tokio::test]
async fn tunnels_to_a_unix_socket() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let sock =
                std::env::temp_dir().join(format!("tightbeam-unix-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&sock);
            let echo = UnixListener::bind(&sock).unwrap();
            tokio::task::spawn_local(async move {
                loop {
                    let (mut conn, _) = echo.accept().await.unwrap();
                    tokio::task::spawn_local(async move {
                        let mut buf = [0u8; 1024];
                        while let Ok(n) = conn.read(&mut buf).await {
                            if n == 0 || conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });

            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_port = probe.local_addr().unwrap().port();
            drop(probe);

            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);

            let service = format!("unix:{}", sock.display());
            tokio::task::spawn_local(async move {
                ExposeCmd {
                    services: vec![service],
                    public: true,
                    quiet: false,
                }
                .run(&exposer, [0u8; 32], None, Brand::TIGHTBEAM)
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

            let mut client = None;
            for _ in 0..100 {
                if let Ok(stream) = TcpStream::connect(("127.0.0.1", local_port)).await {
                    client = Some(stream);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut client = client.expect("consumer never started listening");

            let message = b"over a unix socket";
            client.write_all(message).await.unwrap();
            let mut echoed = vec![0u8; message.len()];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, message);

            let _ = std::fs::remove_file(&sock);
        })
        .await;
}
