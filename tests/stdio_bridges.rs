// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Two stdio bridges, one after the other, in one process: the second gets every byte written to stdin
//! after the first ended.
//!
//! A bridge reads this process's stdin, so the bridges run in a child: this test binary, re-run on the
//! ignored [`child_runs_two_bridges_in_sequence`] with stdin piped. Each bridge reaches a host over the
//! in-process transport that echoes one line, then half-closes, which ends the bridge while stdin stays
//! open.

use core::time::Duration;
use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

use bifrost::{NoDiscovery, Node, Session as _};
use bifrost_mem::MemTransport;
use tightbeam::protocol::{Request, Response};
use tightbeam::tunnel::Connector;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

/// Set in the child's environment, so the ignored child test runs only when this test spawns it.
const CHILD: &str = "TIGHTBEAM_TEST_STDIO_BRIDGES_CHILD";

/// What the child prints to stderr once its first bridge has returned.
const FIRST_ENDED: &str = "first bridge ended";

/// How long a step may take before the test fails rather than hangs.
const WITHIN: Duration = Duration::from_secs(10);

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

/// Serve one session on `host`: admit its stream, echo one line, then half-close. Returns the session,
/// so the caller holds it open until its bridge has read the echo.
async fn echo_one_line(host: &Node<MemTransport, NoDiscovery>) -> impl Sized {
    let session = host.accept().await.unwrap();
    let (mut writer, mut reader) = session.accept_bi().await.unwrap();
    Request::read(&mut reader).await.unwrap();
    Response::Ok.write(&mut writer).await.unwrap();
    let mut line = String::new();
    tokio::io::BufReader::new(reader)
        .read_line(&mut line)
        .await
        .unwrap();
    writer.write_all(line.as_bytes()).await.unwrap();
    writer.shutdown().await.unwrap();
    (session, writer)
}

/// The child: two bridges to the same host, one after the other, on this process's stdin and stdout.
#[tokio::test]
#[ignore = "run only as the child of `a_second_bridge_gets_the_bytes_written_after_the_first_ended`"]
async fn child_runs_two_bridges_in_sequence() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    for marker in [Some(FIRST_ENDED), None] {
        let bridge =
            Connector::to_node(host.node_id(), "echo".parse().unwrap(), None).pipe_stdio(&consumer);
        let (held, bridged) = tokio::join!(echo_one_line(&host), bridge);
        bridged.unwrap();
        drop(held);
        if let Some(marker) = marker {
            eprintln!("{marker}");
        }
    }
}

/// Wait for `text` to appear in what `from` sends, failing past [`WITHIN`].
fn wait_for(from: &mpsc::Receiver<String>, seen: &mut String, text: &str) {
    let deadline = std::time::Instant::now() + WITHIN;
    while !seen.contains(text) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match from.recv_timeout(left) {
            Ok(more) => seen.push_str(&more),
            Err(_) => panic!("never saw {text:?}; saw {seen:?}"),
        }
    }
}

/// Forward everything `from` yields, line by line, to the returned channel.
fn lines(from: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(from).lines() {
            let Ok(line) = line else { return };
            if sender.send(format!("{line}\n")).is_err() {
                return;
            }
        }
    });
    receiver
}

#[test]
fn a_second_bridge_gets_the_bytes_written_after_the_first_ended() {
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args(["child_runs_two_bridges_in_sequence", "--exact", "--ignored"])
            .args(["--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdin = child.0.stdin.take().unwrap();
    let stdout = lines(child.0.stdout.take().unwrap());
    let stderr = lines(child.0.stderr.take().unwrap());
    let (mut out, mut err) = (String::new(), String::new());

    // The first bridge carries its line, then the host ends it while stdin stays open.
    stdin.write_all(b"first line\n").unwrap();
    stdin.flush().unwrap();
    wait_for(&stdout, &mut out, "first line\n");
    wait_for(&stderr, &mut err, FIRST_ENDED);

    // Written only after the first bridge ended: every byte belongs to the second.
    stdin.write_all(b"second line\n").unwrap();
    stdin.flush().unwrap();
    wait_for(&stdout, &mut out, "second line\n");

    drop(stdin);
    let status = child.0.wait().unwrap();
    let mut rest = String::new();
    while let Ok(more) = stderr.try_recv() {
        rest.push_str(&more);
    }
    assert!(status.success(), "the child failed: {err}{rest}");
}
