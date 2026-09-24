// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `tightbeam share`, run as the binary: a link is minted only when the node trusts no signet or trusts
//! its own key. Under a foreign signet a link would be rooted at a key no gate admits, so the verb refuses
//! and prints nothing to stdout.

use std::path::PathBuf;
use std::process::Output;

use bifrost::NodeId;

/// The node's own secret; its public key is what a pin of "self" names.
const OWN_SECRET: [u8; 32] = [7u8; 32];

/// A unique directory under the system temp root, removed on drop even when an assertion fails.
struct TempDir(PathBuf);

impl TempDir {
    /// Make a fresh directory for `tag`; a leftover from a previous crashed run is cleared first.
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("tb-share-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the test dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Persist the node's identity in `dir`, pin `signet` (none: no signet file), and run `share ssh`.
async fn share_under(dir: &TempDir, signet: Option<NodeId>) -> Output {
    let key = dir.0.join("identity.key");
    let signet_path = dir.0.join("signet");
    tightbeam::identity::write(&OWN_SECRET, Some(&key))
        .await
        .expect("persist the node identity");
    if let Some(signet) = signet {
        std::fs::write(&signet_path, format!("{signet}\n")).expect("pin the signet");
    }
    std::process::Command::new(env!("CARGO_BIN_EXE_tightbeam"))
        .args(["share", "ssh"])
        .env("HOME", &dir.0)
        .env("TIGHTBEAM_KEY", &key)
        .env("TIGHTBEAM_SIGNET", &signet_path)
        .output()
        .expect("run tightbeam share")
}

fn own_id() -> NodeId {
    NodeId::from_ed25519_secret(&OWN_SECRET)
}

#[tokio::test]
async fn tightbeam_share_refuses_under_a_foreign_pin() {
    let dir = TempDir::new("foreign");
    let foreign = NodeId::from_ed25519_secret(&[9u8; 32]);
    let output = share_under(&dir, Some(foreign)).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "share must fail under a foreign pin"
    );
    assert!(
        output.stdout.is_empty(),
        "no link may be printed under a foreign pin, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&format!("this node trusts root {foreign}")),
        "the refusal names the pinned root: {stderr}"
    );
    assert!(
        stderr.contains(&format!("this node's key ({})", own_id())),
        "the refusal names the key the link would carry: {stderr}"
    );
}

#[tokio::test]
async fn tightbeam_share_mints_under_its_own_pin() {
    let dir = TempDir::new("own");
    let output = share_under(&dir, Some(own_id())).await;
    assert!(
        output.status.success(),
        "share under its own pin must mint: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let link = String::from_utf8(output.stdout).expect("utf-8 link");
    assert!(link.starts_with("sheer:"), "a link is printed: {link}");
}

#[tokio::test]
async fn tightbeam_share_mints_with_no_pin() {
    let dir = TempDir::new("unpinned");
    let output = share_under(&dir, None).await;
    assert!(
        output.status.success(),
        "share with no signet must mint: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let link = String::from_utf8(output.stdout).expect("utf-8 link");
    assert!(link.starts_with("sheer:"), "a link is printed: {link}");
}
