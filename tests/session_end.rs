// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `connect --to -` ends when the host ends its session: the compiled binary exposes a TCP echo over iroh
//! on loopback, and the compiled binary reaches it as a ProxyCommand does, stdin held open.
//!
//! The holder sends one line, reads it back, then sends nothing. The link it presents expires, the host
//! ends the session within a sweep, and `connect` must exit then, not on the holder's next keystroke.
#![cfg(unix)]

use core::time::Duration;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use bifrost::NodeId;

/// The host's secret; the link roots at its key, which is also the root its gate trusts.
const HOST_SECRET: [u8; 32] = [7u8; 32];

/// The holder's secret.
const HOLDER_SECRET: [u8; 32] = [9u8; 32];

/// How long the link lives: room to dial and echo once on a slow machine before it lapses.
const EXPIRES: Duration = Duration::from_secs(6);

/// How often the host's live cut sweeps, with room for a slow machine.
const SWEEP: Duration = Duration::from_millis(1500);

/// How long `connect` may take to exit once the session has ended.
const EXIT: Duration = Duration::from_secs(4);

/// A scratch dir holding the host's and the holder's homes, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tb-end-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// A home under `scratch` named `name`, holding an identity from `secret`; returns its key file.
async fn home(scratch: &Scratch, name: &str, secret: &[u8; 32]) -> (PathBuf, PathBuf) {
    let home = scratch.0.join(name);
    std::fs::create_dir_all(&home).unwrap();
    let key = home.join("identity.key");
    tightbeam::identity::write(secret, Some(&key))
        .await
        .unwrap();
    (home, key)
}

/// A `tightbeam` command run on `home` under `key`, with no root or denylist from the real home.
fn tightbeam(home: &Path, key: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tightbeam"));
    command
        .env("HOME", home)
        .env("TIGHTBEAM_KEY", key)
        .env_remove("TIGHTBEAM_ROOT")
        .env_remove("TIGHTBEAM_REVOKED");
    command
}

/// A TCP echo on loopback, served by a thread per connection; returns its port.
fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for connection in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = connection.try_clone().unwrap();
                let mut writer = connection;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });
    port
}

/// A UDP port on loopback free a moment ago, for the host to bind.
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .unwrap()
        .port()
}

/// Read one line from `from`, failing past `deadline` rather than hanging the run.
fn line_within(from: impl std::io::Read + Send + 'static, deadline: Duration) -> String {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(from).read_line(&mut line);
        let _ = sender.send(line);
    });
    receiver
        .recv_timeout(deadline)
        .expect("a line arrives within the deadline")
}

#[tokio::test]
async fn connect_to_stdout_exits_when_the_host_ends_the_session_while_stdin_is_silent() {
    let scratch = Scratch::new("stdio");
    let host_id = NodeId::from_ed25519_secret(&HOST_SECRET);
    let (host_home, host_key) = home(&scratch, "host", &HOST_SECRET).await;
    let (holder_home, holder_key) = home(&scratch, "holder", &HOLDER_SECRET).await;
    // The host trusts its own key as root, so a link it mints is admitted and its expiry is enforced live.
    let root = host_home.join("root");
    std::fs::write(&root, format!("{host_id}\n")).unwrap();

    // Expose the echo on a fixed loopback address, and wait for the banner.
    let addr = format!("127.0.0.1:{}", free_udp_port());
    let mut host = tightbeam(&host_home, &host_key)
        .env("TIGHTBEAM_ROOT", &root)
        .args(["--bind-addr", &addr, "expose"])
        .arg(format!("echo=tcp:127.0.0.1:{}", echo()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut banner = BufReader::new(host.stderr.take().unwrap()).lines();
    let _host = KillOnDrop(host);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "expose never printed its banner");
        let line = banner
            .next()
            .expect("expose exited before its banner")
            .unwrap();
        if line.starts_with("exposing ") {
            break;
        }
    }
    // Keep draining the host's stderr so it never blocks on a full pipe.
    std::thread::spawn(move || for _ in banner {});

    let expires = format!("{}s", EXPIRES.as_secs());
    let shared = tightbeam(&host_home, &host_key)
        .env("TIGHTBEAM_ROOT", &root)
        .args(["share", "echo", "--expires", &expires])
        .output()
        .unwrap();
    assert!(shared.status.success(), "share mints the link");
    let lapses = Instant::now() + EXPIRES;
    let link = String::from_utf8(shared.stdout).unwrap();

    let mut connect = KillOnDrop(
        tightbeam(&holder_home, &holder_key)
            .args([
                "--peer",
                &format!("{host_id}={addr}"),
                "--offline",
                "connect",
            ])
            .args([link.trim(), "--service", "echo", "--to", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut err_pipe = connect.0.stderr.take().unwrap();
    let stderr = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err_pipe.read_to_string(&mut text);
        text
    });

    // One line there and back: the session is open. Then stdin stays open and silent, as a terminal is.
    let mut stdin = connect.0.stdin.take().unwrap();
    stdin.write_all(b"still here\n").unwrap();
    stdin.flush().unwrap();
    assert_eq!(
        line_within(connect.0.stdout.take().unwrap(), EXPIRES),
        "still here\n",
        "the link is admitted and the echo answers before it lapses"
    );
    assert!(
        Instant::now() < lapses,
        "the echo came back before the link lapsed, so the end below is the expiry's"
    );

    let deadline = lapses + SWEEP + EXIT;
    let status = loop {
        if let Some(status) = connect.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "connect is still running after the host ended its session"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !status.success(),
        "a session the host ended exits nonzero: {status}, {}",
        stderr.join().unwrap()
    );
    drop(stdin);
}
