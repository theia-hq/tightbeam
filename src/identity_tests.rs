//! Unit tests for the persisted identity: fail-closed load, mint-on-absence, a write that never
//! replaces a different key, the bridge between a `NodeId` and a `VerifyKey`, and a locked file's key
//! as a `NodeId`.

use std::path::{Path, PathBuf};

use bifrost::{CryptoKind, NodeId};
use keystore::{Error, FormatError};

use crate::identity::{AsNodeId as _, AsVerifyKey as _, IdentityError, load, write};

/// A unique directory under the system temp root, removed on drop even when an assertion fails.
struct TempDir(PathBuf);

impl TempDir {
    /// Make a fresh directory for `tag`; a leftover from a previous crashed run is cleared first.
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("tb-identity-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the test dir");
        Self(path)
    }

    /// The conventional key path inside this test's directory.
    fn key(&self) -> PathBuf {
        self.0.join("identity.key")
    }

    /// The directory itself, to lock or list.
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A test that locked the dir read-only must still clean up.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Seed a file with exact bytes and mode, as a prior writer (or a corrupted copy) would have left it.
#[cfg(unix)]
fn seed(path: &Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, bytes).expect("seed the file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set the mode");
}

#[cfg(not(unix))]
fn seed(path: &Path, bytes: &[u8], _mode: u32) {
    std::fs::write(path, bytes).expect("seed the file");
}

/// A mint happens only when the file is absent: the fresh key lands at 0600, and a second load reads that
/// same key back rather than minting another.
#[tokio::test]
async fn absent_file_mints_and_persists_once() {
    let dir = TempDir::new("mint");
    let path = dir.key();

    let minted = load(Some(&path))
        .await
        .expect("mint on absence")
        .with_bytes(|seed| *seed);
    assert_eq!(
        std::fs::read(&path).expect("read the minted key"),
        minted.to_vec(),
        "the mint persisted exactly"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("stat the key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the minted key is owner-only");
    }

    let reloaded = load(Some(&path)).await.expect("load the persisted key");
    assert_eq!(
        reloaded.with_bytes(|seed| *seed),
        minted,
        "a present key is loaded, never re-minted"
    );
}

/// The regression: a wrong-size file is a typed refusal and its bytes survive, where the old loader
/// minted a fresh key over it.
#[tokio::test]
async fn wrong_size_is_refused_and_the_file_survives() {
    let dir = TempDir::new("wrong-size");
    let path = dir.key();

    for size in [33usize, 31, 0] {
        let bytes = vec![9u8; size];
        seed(&path, &bytes, 0o600);

        let Err(error) = load(Some(&path)).await else {
            panic!("a wrong-size file must be refused");
        };
        assert!(
            matches!(
                error,
                IdentityError::Key(Error::Format {
                    source: FormatError::Size { found },
                    ..
                }) if found == size as u64
            ),
            "unexpected error for {size} bytes: {error}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read back"),
            bytes,
            "the file is untouched"
        );
    }
}

/// A group- or world-readable key is refused with its mode in the error and the bytes intact; the guard
/// is load-only, so tightening the mode makes the same file load.
#[cfg(unix)]
#[tokio::test]
async fn permissive_mode_is_refused_until_tightened() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("permissive");
    let path = dir.key();
    seed(&path, &[5u8; 32], 0o644);

    let Err(error) = load(Some(&path)).await else {
        panic!("0644 must be refused");
    };
    assert!(
        matches!(
            error,
            IdentityError::Key(Error::Permissive { mode: 0o644, .. })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        [5u8; 32].to_vec(),
        "the file survives the refusal"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("tighten the mode");
    let loaded = load(Some(&path)).await.expect("a tightened key loads");
    assert_eq!(loaded.with_bytes(|seed| *seed), [5u8; 32]);
}

/// The partial-write case: when the sibling stage cannot be created nothing lands, and the refusal is
/// the store's own typed error rather than a half-written key.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_write_leaves_nothing() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("failed-write");
    let path = dir.key();

    // 0500 on the parent blocks the sibling stage.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
        .expect("lock the dir");
    let refused = write(&[2u8; 32], Some(&path)).await;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("unlock the dir");

    assert!(
        matches!(&refused, Err(IdentityError::Key(Error::Io { .. }))),
        "a stage that cannot create is a typed store error, got {refused:?}"
    );
    assert!(!path.exists(), "a failed write lands no key");
}

/// A write into a path that already holds a DIFFERENT key is refused and the key survives byte for byte:
/// that key may be the only copy there is. Writing the key already there is a no-op, so adopting twice
/// is harmless.
///
/// The survival assertion comes first, so with the refusal removed it is the one that fails.
#[tokio::test]
async fn a_write_never_replaces_a_different_key() {
    let dir = TempDir::new("replace");
    let path = dir.key();
    write(&[1u8; 32], Some(&path)).await.expect("first write");

    let refused = write(&[2u8; 32], Some(&path)).await;
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        [1u8; 32].to_vec(),
        "the key already there survives"
    );
    assert!(
        matches!(&refused, Err(IdentityError::Key(Error::Different { .. }))),
        "a different key is refused by name, got {refused:?}"
    );

    write(&[1u8; 32], Some(&path))
        .await
        .expect("writing the key already there is a no-op");
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("list the dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .collect();
    assert_eq!(
        entries,
        vec![std::ffi::OsString::from("identity.key")],
        "no staging file is left behind"
    );
}

/// A sealed key file is refused, never read as absent: minting over it would destroy the key it seals.
#[tokio::test]
async fn a_sealed_key_is_refused_and_survives() {
    let dir = TempDir::new("sealed");
    let path = dir.key();
    let passphrase =
        keystore::Passphrase::new(zeroize::Zeroizing::new(b"hunter2".to_vec())).expect("non-empty");
    let secret = keystore::Secret::take(&mut [3u8; 32]);
    keystore::KeyFile::new(path.as_path())
        .write(&secret, keystore::Protection::Passphrase(&passphrase))
        .expect("seal a key");
    let sealed = std::fs::read(&path).expect("read the sealed file");

    let refused = load(Some(&path)).await;
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        sealed,
        "the sealed file survives"
    );
    assert!(
        matches!(&refused, Err(IdentityError::Sealed { .. })),
        "a sealed file is refused as sealed"
    );
}

/// A strict key at the identity path is refused as the wrong kind, by load and by write, and survives
/// both: the identity is a standard key, and a strict key is never taken for one.
#[tokio::test]
async fn a_strict_key_is_refused_by_its_kind_and_survives() {
    let dir = TempDir::new("strict-kind");
    let path = dir.key();
    let passphrase =
        keystore::Passphrase::new(zeroize::Zeroizing::new(b"hunter2".to_vec())).expect("non-empty");
    let secret = keystore::Secret::take(&mut [5u8; 32]);
    keystore::KeyFile::strict(path.as_path())
        .write(&secret, keystore::Protection::Passphrase(&passphrase))
        .expect("seal a strict key");
    let sealed = std::fs::read(&path).expect("read the strict key");

    let wrong_kind = |refused: &Result<_, IdentityError>| {
        matches!(
            refused,
            Err(IdentityError::Key(keystore::Error::Format {
                source: keystore::FormatError::WrongKind {
                    expected: keystore::Kind::Standard,
                    found: keystore::Kind::Strict,
                },
                ..
            }))
        )
    };
    let loaded = load(Some(&path)).await.map(drop);
    assert!(
        wrong_kind(&loaded),
        "a strict key is refused by its kind on load, got {loaded:?}"
    );
    let written = write(&[5u8; 32], Some(&path)).await;
    assert!(
        wrong_kind(&written),
        "a strict key is refused by its kind on write, got {written:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        sealed,
        "the strict key survives"
    );
}

/// A path that names a directory is a teaching refusal, not an OS error the user must decode.
#[tokio::test]
async fn a_directory_is_refused() {
    let dir = TempDir::new("directory");
    let path = dir.key();
    std::fs::create_dir_all(&path).expect("make the directory the path names");

    let Err(error) = load(Some(&path)).await else {
        panic!("a directory is not a key file");
    };
    assert!(
        matches!(error, IdentityError::Directory { .. }),
        "unexpected error: {error}"
    );
}

/// A mint under a fresh directory creates it owner-only, like the key inside it.
#[cfg(unix)]
#[tokio::test]
async fn a_fresh_key_directory_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("fresh-dir");
    let path = dir.path().join("nested").join("identity.key");
    load(Some(&path))
        .await
        .expect("mint under a fresh directory");
    let mode = std::fs::metadata(dir.path().join("nested"))
        .expect("stat the directory")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "the key's directory is owner-only");
}

/// The public key of `seed`, named on nauthy's side from the secret itself, so the bridge is checked
/// against a key it did not produce.
fn verify_key_of(seed: &[u8; 32]) -> nauthy::VerifyKey {
    nauthy::Identity::from_secret(seed)
        .expect("a seed is a secret")
        .verifying_key()
}

/// A `NodeId` and the `VerifyKey` of the same secret are the same key.
#[test]
fn same_key_matches_the_same_bytes() {
    let seed = [7u8; 32];
    let id = NodeId::from_ed25519_secret(&seed);
    assert!(id.same_key(&verify_key_of(&seed)));
}

/// A `NodeId` is not the same key as a `VerifyKey` of other bytes.
///
/// `CryptoKind` has one suite, so a `NodeId` of another suite cannot be built to test the suite half.
/// That half is checked by the compiler instead: `same_key` matches on the suite with no catch-all, so a
/// second suite does not build until its arm is written.
#[test]
fn same_key_refuses_other_bytes() {
    let id = NodeId::from_ed25519_secret(&[7u8; 32]);
    assert!(!id.same_key(&verify_key_of(&[8u8; 32])));
}

/// Only an ed25519 `NodeId` converts to a `VerifyKey`, and to the key of the same bytes.
///
/// `CryptoKind` has one suite, so a `NodeId` of another suite cannot be built. The match below names
/// every suite with no catch-all, so a second suite does not build until it is given its expectation
/// here: that its `NodeId` is refused.
#[test]
fn an_ed25519_node_id_converts_to_its_own_verify_key() {
    let seed = [7u8; 32];
    let id = NodeId::from_ed25519_secret(&seed);
    match id.kind() {
        CryptoKind::Ed25519 => assert_eq!(id.verify_key(), Ok(verify_key_of(&seed))),
    }
}

/// A sealed file whose header claims a real key converts to the `NodeId` of the seed it seals.
#[test]
fn a_locked_files_key_converts_to_its_node_id() {
    let dir = TempDir::new("locked-key");
    let path = dir.key();
    let seed = [7u8; 32];
    seal_standard_key(&path, &seed);

    let claimed = locked_public_key(&path);
    assert_eq!(claimed.node_id(), Ok(NodeId::from_ed25519_secret(&seed)));
}

/// A sealed file whose header claims bytes no ed25519 key can be is refused at the conversion, with
/// bifrost's reason, rather than becoming a `NodeId`.
#[test]
fn a_locked_files_malformed_key_is_refused() {
    let dir = TempDir::new("locked-malformed");
    let path = dir.key();
    seal_standard_key(&path, &[7u8; 32]);
    // The header's public key sits at bytes 10..42 of a sealed file (keystore's frozen layout:
    // signature 8, version 1, kind 1). Nothing checks it before an unlock, so a forged claim loads.
    let mut bytes = std::fs::read(&path).expect("read the sealed file");
    bytes[10..42].copy_from_slice(&[2u8; 32]);
    std::fs::write(&path, &bytes).expect("forge the header");

    let claimed = locked_public_key(&path);
    assert_eq!(claimed.node_id(), Err(bifrost::KeyError::NotOnCurve));
}

/// Seal `seed` as a standard key at `path` under a throwaway passphrase.
fn seal_standard_key(path: &Path, seed: &[u8; 32]) {
    let passphrase =
        keystore::Passphrase::new(zeroize::Zeroizing::new(b"hunter2".to_vec())).expect("non-empty");
    let secret = keystore::Secret::take(&mut { *seed });
    keystore::KeyFile::new(path)
        .write(&secret, keystore::Protection::Passphrase(&passphrase))
        .expect("seal a key");
}

/// The public key the sealed standard key file at `path` claims, read without unlocking.
fn locked_public_key(path: &Path) -> keystore::PublicKey {
    match keystore::KeyFile::new(path).load() {
        Ok(Some(keystore::Stored::Locked(locked))) => locked.public_key(),
        other => panic!("expected a locked key file, got {other:?}"),
    }
}
