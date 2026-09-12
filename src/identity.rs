//! The node identity: the ed25519 secret tightbeam binds under and roots capabilities at.
//!
//! A capability roots at the exposer's `NodeId`, and verifying a presented cap needs the exposer to hold
//! the matching secret, so the exposer must have a *stable* identity across runs, not the fresh key a
//! throwaway dial would use. The same secret does double duty: bifrost binds the transport under it (so
//! the node is reachable at a stable `NodeId`) and [`nauthy::Identity`] roots caps at it (so a minted cap
//! verifies against the identity peers dial). It persists at `~/.config/tightbeam/identity.key`, mode
//! 0600, overridable with an explicit key path (or `TIGHTBEAM_KEY`).
//!
//! Loading is fail-closed. An ABSENT file mints a fresh key and saves it; a file that is present but does
//! not decode as exactly one 32-byte seed (wrong size, unreadable, a directory, a mode group or other can
//! read) is an [`IdentityError`] naming the path, and it is never overwritten: a truncated or corrupted
//! key is a hard error, not a new identity. Every write stages a sibling temp file, fsyncs it, and renames
//! it over the target, so a crash leaves the old key or the complete new one, never a torn file.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes on drop so the key does not
//! linger in freed memory, and it is unwrapped only at the two boundaries that need it raw, the transport
//! bind and the cap root.

use std::io;
use std::path::{Path, PathBuf};

use bifrost::{CryptoKind, NodeId};
use nauthy::VerifyKey;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::{Zeroize as _, ZeroizeOnDrop, Zeroizing};

/// The bridge between bifrost's [`NodeId`] and nauthy's [`VerifyKey`]: two names for one ed25519 public
/// key on either side of the cap/transport boundary.
///
/// nauthy is standalone (it carries no bifrost dependency), so it names a key by [`VerifyKey`] while
/// bifrost names the same key by [`NodeId`]. Both are the same 32 raw bytes under the same `bf01` string
/// form, so the conversion is an infallible byte copy. It lives here, at the one crate that sees both
/// types, so no call site open-codes the byte shuffle. The orphan rule forbids a `From` impl (both types
/// are foreign to tightbeam), hence the extension traits.
pub trait AsVerifyKey {
    /// This identity as a nauthy [`VerifyKey`] (the type caps root at and gates admit).
    fn verify_key(&self) -> VerifyKey;
}

impl AsVerifyKey for NodeId {
    fn verify_key(&self) -> VerifyKey {
        VerifyKey::new(*self.key())
    }
}

/// The other direction: a [`VerifyKey`] back to the bifrost [`NodeId`] a peer is dialed at.
pub trait AsNodeId {
    /// This key as a bifrost [`NodeId`], tagged ed25519 (the only suite these keys carry).
    fn node_id(&self) -> NodeId;
}

impl AsNodeId for VerifyKey {
    fn node_id(&self) -> NodeId {
        NodeId::new(CryptoKind::Ed25519, *self.bytes())
    }
}

/// The ed25519 secret key the node binds under and roots capabilities at. Wraps the raw bytes so they
/// zeroize on drop and never cross a boundary as a bare array.
#[derive(ZeroizeOnDrop)]
pub struct Secret([u8; 32]);

impl Secret {
    /// A fresh random secret, kept only in memory. `rand::random` draws from a CSPRNG seeded by the OS,
    /// the same source every ephemeral key mint draws from.
    pub fn ephemeral() -> Self {
        Self(rand::random())
    }

    /// The cap-signing identity rooted at this secret. Borrows, so the secret stays owned here and
    /// zeroizes on drop after the transport has also consumed a copy.
    pub fn cap_identity(&self) -> eyre::Result<nauthy::Identity> {
        Ok(nauthy::Identity::from_secret(&self.0)?)
    }

    /// Consume the secret into its raw bytes for the transport bind. The single boundary where the key
    /// leaves the zeroizing wrapper; the transport crate owns the key type downstream.
    pub fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        // Wipe our copy; the returned array is the caller's to own from here.
        self.0.zeroize();
        bytes
    }
}

/// Why a persisted identity could not be loaded or written.
///
/// Each variant names the file and the reason, so a caller can tell a file that is genuinely absent (the
/// one case [`load`] mints) from a present file it must refuse rather than replace.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Neither an explicit path nor `HOME`/`TIGHTBEAM_KEY` named the key file.
    #[error("HOME is not set; set an explicit key path (or TIGHTBEAM_KEY)")]
    NoHome,
    /// The file exists but could not be opened or read.
    #[error("failed to read identity file {}", .path.display())]
    Read {
        /// The path the load was pointed at.
        path: PathBuf,
        /// The underlying IO failure.
        #[source]
        source: io::Error,
    },
    /// The path names a directory, not a key file.
    #[error(
        "identity key path {} is a directory, not a key file; name a file inside it, e.g. {}/identity.key",
        .path.display(),
        .path.display()
    )]
    Directory {
        /// The directory the load was pointed at.
        path: PathBuf,
    },
    /// The file exists but does not hold exactly one 32-byte ed25519 seed.
    #[error(
        "identity file {} does not hold a 32-byte ed25519 seed ({size} bytes read); refusing to replace it",
        .path.display()
    )]
    Malformed {
        /// The malformed file.
        path: PathBuf,
        /// How many bytes were read before the size check failed.
        size: u64,
    },
    /// Group or other holds a permission bit on the seed.
    #[error(
        "permissions {mode:04o} for identity file {} are too open: group or other can read the seed. run `chmod 600 {}`",
        .path.display(),
        .path.display()
    )]
    Permissive {
        /// The over-exposed file.
        path: PathBuf,
        /// The file mode that failed the guard.
        mode: u32,
    },
    /// The file could not be written.
    #[error("failed to write identity file {}", .path.display())]
    Write {
        /// The target path.
        path: PathBuf,
        /// The underlying IO failure.
        #[source]
        source: io::Error,
    },
}

/// Write a provided secret as this node's persisted identity: how a machine ADOPTS a minted device seed
/// to BECOME that identity. This is the deliberate replacement path: it overwrites any key at the path on
/// purpose (adopting replaces this node's identity), so unlike [`load`] it needs no absence check. The
/// write stages a sibling temp file, fsyncs it, and renames it over the target at mode 0600, so a crash
/// cannot leave a partial key. The path is the explicit one (or `TIGHTBEAM_KEY`) or the default; the
/// exposer then binds under it.
pub async fn write(secret: &[u8; 32], explicit: Option<&Path>) -> Result<(), IdentityError> {
    let path = resolve_path(explicit)?;
    write_atomic(&path, secret)
        .await
        .map_err(|source| IdentityError::Write { path, source })
}

/// Load the persisted secret, minting and saving a fresh one ONLY when the file is genuinely absent.
///
/// An explicit path (or `TIGHTBEAM_KEY`) overrides the default location. tightbeam's identity is always
/// persisted (unlike an ephemeral reach-outward client) because a cap exposer must be reachable and
/// verifiable at one stable key across runs. A file that is present but does not decode (wrong size,
/// unreadable, a directory, a group/world-readable mode) is an [`IdentityError`], never overwritten and
/// never replaced with a freshly minted key.
pub async fn load(explicit: Option<&Path>) -> Result<Secret, IdentityError> {
    let path = resolve_path(explicit)?;
    match tokio::fs::File::open(&path).await {
        Ok(file) => decode(&path, file).await,
        // The ONLY mint path, and only because nothing is there to destroy.
        Err(error) if error.kind() == io::ErrorKind::NotFound => mint(&path).await,
        Err(source) => Err(IdentityError::Read { path, source }),
    }
}

/// Resolve the explicit key path, or the persisted default when none was given.
fn resolve_path(explicit: Option<&Path>) -> Result<PathBuf, IdentityError> {
    match explicit {
        Some(path) => Ok(path.to_owned()),
        None => default_path(),
    }
}

/// Decode an already-open identity file: exactly one 32-byte seed, owner-only.
///
/// The mode guard and the size check both read from THIS handle (fstat the fd, read the same fd), so a
/// swap between the check and the read cannot slip a different file past either, and a present file that
/// fails is closed unread rather than rewritten.
async fn decode(path: &Path, file: tokio::fs::File) -> Result<Secret, IdentityError> {
    let metadata = file
        .metadata()
        .await
        .map_err(|source| IdentityError::Read {
            path: path.to_owned(),
            source,
        })?;
    if metadata.is_dir() {
        return Err(IdentityError::Directory {
            path: path.to_owned(),
        });
    }
    guard_file_perms(&metadata, path)?;
    // Read one byte PAST the seed: enough to tell a short file from a long one, and a bound on what a
    // runaway source (a huge file, `/dev/zero`) can pull in before the size check refuses it.
    let mut bytes = Zeroizing::new(Vec::with_capacity(32));
    file.take(33)
        .read_to_end(&mut bytes)
        .await
        .map_err(|source| IdentityError::Read {
            path: path.to_owned(),
            source,
        })?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| IdentityError::Malformed {
        path: path.to_owned(),
        size: bytes.len() as u64,
    })?;
    Ok(Secret(seed))
}

/// Mint a fresh key and persist it atomically. Reached only from [`load`], only when the file is absent.
async fn mint(path: &Path) -> Result<Secret, IdentityError> {
    let secret = Secret::ephemeral();
    write_atomic(path, &secret.0)
        .await
        .map_err(|source| IdentityError::Write {
            path: path.to_owned(),
            source,
        })?;
    Ok(secret)
}

/// Stage `secret` in a sibling temp file, fsync it, and rename it over `path`. The rename is atomic, so a
/// crash or a full disk leaves the old key or the complete new one, never a torn file; a failed stage
/// cleans its temp up.
async fn write_atomic(path: &Path, secret: &[u8; 32]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temp = temp_path(path);
    let staged = async {
        let mut file = create_private(&temp).await?;
        file.write_all(secret).await?;
        file.sync_all().await
    }
    .await;
    let outcome = match staged {
        Ok(()) => tokio::fs::rename(&temp, path).await,
        Err(error) => Err(error),
    };
    if outcome.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
    }
    outcome
}

/// A unique staging path BESIDE `path`, so the rename that publishes it is same-directory and atomic. The
/// pid plus a random suffix keep two writers apart and keep a stale temp from a crashed writer from being
/// reused.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_owned())
        .unwrap_or_default();
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    path.with_file_name(name)
}

/// Create the staging file new and owner-only. `create_new` refuses a path a concurrent writer already
/// staged; the mode is set AT creation (`0600` on unix), so the seed is never group/world-readable, not
/// even for the instant before a chmod could tighten it.
#[cfg(unix)]
async fn create_private(path: &Path) -> io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await
}

/// Non-unix has no file-mode equivalent; the staging file is created new and written as given.
#[cfg(not(unix))]
async fn create_private(path: &Path) -> io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
}

/// Refuse a group- or world-accessible identity file: the seed IS the node, so any bit beyond owner-only
/// is a leak, and reading what the guard warns about would defeat the point. Mirrors the `@<path>` secret
/// reader's check. The mode comes from the OPEN handle (`fstat`), and the caller reads that same handle,
/// so nothing can swap a strict file for a permissive one between the check and the read.
#[cfg(unix)]
fn guard_file_perms(metadata: &std::fs::Metadata, path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::MetadataExt as _;

    let mode = metadata.mode();
    if mode & 0o077 != 0 {
        return Err(IdentityError::Permissive {
            path: path.to_owned(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

/// Non-unix has no portable file-mode equivalent, so the guarantee is unix-only and the file is read as
/// given. Fabricating a bogus check here would give false assurance, so we deliberately do nothing.
#[cfg(not(unix))]
fn guard_file_perms(_metadata: &std::fs::Metadata, _path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// The default persisted key location, `~/.config/tightbeam/identity.key`.
fn default_path() -> Result<PathBuf, IdentityError> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_KEY") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or(IdentityError::NoHome)?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("tightbeam")
        .join("identity.key"))
}
