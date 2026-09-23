//! The node identity: the ed25519 secret tightbeam binds under and roots capabilities at.
//!
//! A capability roots at the exposer's `NodeId`, and verifying a presented cap needs the exposer to hold
//! the matching secret, so the exposer must have a *stable* identity across runs, not the fresh key a
//! throwaway dial would use. The same secret does double duty: bifrost binds the transport under it (so
//! the node is reachable at a stable `NodeId`) and [`nauthy::Identity`] roots caps at it (so a minted cap
//! verifies against the identity peers dial). It persists at `~/.config/tightbeam/identity.key`, mode
//! 0600, overridable with an explicit key path (or `TIGHTBEAM_KEY`).
//!
//! The file is a [`keystore`] key file, so its bytes, its owner-only guard, and its atomic writes follow
//! that crate's one format. Loading is fail-closed. An ABSENT file mints a fresh key and saves it; a file
//! that is present but does not load (wrong size, unreadable, a directory, a mode group or other can read,
//! an owner that is not this user) is an [`IdentityError`] naming the path, and it is never overwritten: a
//! truncated or corrupted key is a hard error, not a new identity. A file sealed under a passphrase is
//! refused too, because tightbeam has no way to ask for one; it is never read as absent.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes on drop so the key does not
//! linger in freed memory, and it is lent out only at the two boundaries that need it raw, the transport
//! bind and the cap root.

use std::path::{Path, PathBuf};

use bifrost::{CryptoKind, NodeId};
use keystore::{KeyFile, Protection, Stored};
use nauthy::VerifyKey;
use zeroize::{ZeroizeOnDrop, Zeroizing};

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

/// The ed25519 secret key the node binds under and roots capabilities at: a [`keystore::Secret`], which
/// wipes itself on drop and never hands its bytes out by value.
pub struct Secret(keystore::Secret);

/// The inner secret wipes itself on drop, so this one does.
impl ZeroizeOnDrop for Secret {}

impl Secret {
    /// A fresh random secret, kept only in memory. `rand::random` draws from a CSPRNG seeded by the OS,
    /// the same source every ephemeral key mint draws from; the stack copy is wiped as it is taken in.
    pub fn ephemeral() -> Self {
        let mut seed: [u8; 32] = rand::random();
        Self(keystore::Secret::take(&mut seed))
    }

    /// The cap-signing identity rooted at this secret. Borrows, so the secret stays owned here.
    pub fn cap_identity(&self) -> eyre::Result<nauthy::Identity> {
        Ok(self.0.with_bytes(nauthy::Identity::from_secret)?)
    }

    /// Lend the raw seed to `lend` for the length of the call: for the transport bind, which borrows
    /// the seed and returns a future that no longer does, so no copy of it leaves this wrapper.
    pub fn with_bytes<R>(&self, lend: impl FnOnce(&[u8; 32]) -> R) -> R {
        self.0.with_bytes(lend)
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
    /// The file is sealed under a passphrase, and tightbeam has no way to ask for one.
    #[error(
        "identity file {} is sealed under a passphrase, which tightbeam cannot unlock; point it at a plain key",
        .path.display()
    )]
    Sealed {
        /// The sealed file.
        path: PathBuf,
    },
    /// The directory the key file lives in could not be created.
    #[error("failed to create the identity directory {}", .path.display())]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// The underlying IO failure.
        #[source]
        source: std::io::Error,
    },
    /// The operating system's random source failed, so no key was minted.
    #[error("could not draw a fresh identity key from the system's random source")]
    Entropy(#[source] keystore::CryptoError),
    /// The key file store refused: the file could not be read, is not a key, is readable by others, or
    /// already holds a different key.
    #[error(transparent)]
    Key(#[from] keystore::Error),
}

/// Write a provided secret as this node's persisted identity: how a machine ADOPTS a minted device seed
/// to BECOME that identity. Writes into absence; a file already holding this same key is left as it is,
/// and a file holding a DIFFERENT key is refused ([`keystore::Error::Different`]) and never replaced,
/// because that key may be the only copy there is. The path is the explicit one (or `TIGHTBEAM_KEY`) or
/// the default; the exposer then binds under it.
pub async fn write(secret: &[u8; 32], explicit: Option<&Path>) -> Result<(), IdentityError> {
    let file = key_file(explicit)?;
    create_parent(file.path())?;
    let mut seed = Zeroizing::new(*secret);
    let secret = keystore::Secret::take(&mut seed);
    Ok(file.adopt(&secret, Protection::Plain)?)
}

/// Load the persisted secret, minting and saving a fresh one ONLY when the file is genuinely absent.
///
/// An explicit path (or `TIGHTBEAM_KEY`) overrides the default location. tightbeam's identity is always
/// persisted (unlike an ephemeral reach-outward client) because a cap exposer must be reachable and
/// verifiable at one stable key across runs. A file that is present but does not load is an
/// [`IdentityError`], never overwritten and never replaced with a freshly minted key.
///
/// The store is synchronous: it runs once, at startup, before any task this process spawns.
pub async fn load(explicit: Option<&Path>) -> Result<Secret, IdentityError> {
    let file = key_file(explicit)?;
    if let Some(secret) = open(&file)? {
        return Ok(secret);
    }
    // The ONLY mint path, and only because nothing is there to destroy.
    let secret = keystore::Secret::generate().map_err(IdentityError::Entropy)?;
    create_parent(file.path())?;
    file.write(&secret, Protection::Plain)?;
    Ok(Secret(secret))
}

/// The key file at the explicit path, or the persisted default when none was given.
fn key_file(explicit: Option<&Path>) -> Result<KeyFile, IdentityError> {
    match explicit {
        Some(path) => Ok(KeyFile::from(path)),
        None => default_path().map(KeyFile::from),
    }
}

/// The key the file holds, or `None` only when nothing is at the path.
fn open(file: &KeyFile) -> Result<Option<Secret>, IdentityError> {
    match file.load() {
        Ok(None) => Ok(None),
        Ok(Some(Stored::Plain(secret))) => Ok(Some(Secret(secret))),
        Ok(Some(Stored::Locked(_))) => Err(IdentityError::Sealed {
            path: file.path().to_owned(),
        }),
        // A directory at the key path is the one refusal with a fix worth teaching: name a file in it.
        Err(keystore::Error::NotAFile { path }) if path.is_dir() => {
            Err(IdentityError::Directory { path })
        }
        Err(error) => Err(error.into()),
    }
}

/// Create the directory the key file lives in, owner-only, so a first run under a fresh home can mint.
fn create_parent(path: &Path) -> Result<(), IdentityError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    // Owner-only, like the key it holds: a directory others can list shows who holds a key and when it
    // changed. A directory that already exists is left as its owner set it.
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(parent)
        .map_err(|source| IdentityError::CreateDir {
            path: parent.to_owned(),
            source,
        })
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
