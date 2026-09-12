//! Unit tests for the persisted identity: fail-closed load, mint-on-absence, and the atomic write.

use std::path::{Path, PathBuf};

use crate::identity::{IdentityError, load, write};

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
        .into_bytes();
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
        reloaded.into_bytes(),
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
            matches!(error, IdentityError::Malformed { size: read, .. } if read == size as u64),
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
        matches!(error, IdentityError::Permissive { mode: 0o644, .. }),
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
    assert_eq!(loaded.into_bytes(), [5u8; 32]);
}

/// The partial-write case: when the sibling stage cannot be created the previous key survives byte for
/// byte, because the writer never touches the target until the rename.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_write_leaves_the_previous_key() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("failed-write");
    let path = dir.key();
    let previous = [1u8; 32];
    write(&previous, Some(&path)).await.expect("first write");

    // 0500 on the parent blocks the sibling stage while the target itself stays writable, so an
    // in-place writer would have truncated it; the atomic one refuses and leaves it alone.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
        .expect("lock the dir");
    let refused = write(&[2u8; 32], Some(&path)).await;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("unlock the dir");

    assert!(
        matches!(&refused, Err(IdentityError::Write { .. })),
        "a stage that cannot create is a typed write error, got {refused:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        previous.to_vec(),
        "the previous key survives the failed write"
    );
}

/// A write replaces the key through a rename and leaves only the one file: no staging temp survives.
#[tokio::test]
async fn write_replaces_atomically_leaving_one_file() {
    let dir = TempDir::new("replace");
    let path = dir.key();
    write(&[1u8; 32], Some(&path)).await.expect("first write");

    #[cfg(unix)]
    let before = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(&path).expect("stat before").ino()
    };

    write(&[2u8; 32], Some(&path))
        .await
        .expect("replace the key");
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        [2u8; 32].to_vec(),
        "the new key is in place"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let after = std::fs::metadata(&path).expect("stat after").ino();
        assert_ne!(
            before, after,
            "the target is a renamed new inode, not a truncated one"
        );
    }

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("list the dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .collect();
    assert_eq!(
        entries,
        vec![std::ffi::OsString::from("identity.key")],
        "the temp was renamed, not left behind"
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
