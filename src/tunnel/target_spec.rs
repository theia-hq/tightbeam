use core::str::FromStr;
use std::path::Path;

/// A syntax-checked primitive target. Parsing does not prepare a backend or access the filesystem.
///
/// Supported forms are `tcp:<host>:<port>`, `unix:<path>`, `file:<path>`, `fifo:<path>`, `stdin:`, and
/// `echo:`. Schemes are case-sensitive. TCP requires a nonempty host and a `u16` port, including zero;
/// parsing does not resolve the host. Paths must be nonempty. `stdin:` and `echo:` take no argument.
/// One trailing `+lossy` suffix is recognized, only for FIFO and stdin targets.
///
/// Equality compares retained target text.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    text: String,
    kind: Kind,
}

impl TargetSpec {
    /// Return the retained target text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Join relative target paths to `cwd` without filesystem access. `cwd` must be absolute, even for
    /// unchanged targets. Absolute paths and non-path targets remain unchanged. Path spelling is
    /// preserved: `~`, `.` and `..` are not expanded or normalized. On Windows, drive-relative and
    /// root-relative paths cannot be anchored; use an absolute path or a relative path without a drive
    /// prefix or root.
    ///
    /// # Errors
    ///
    /// Returns an error if `cwd` is not absolute, the joined path is not UTF-8, or a Windows target path
    /// is drive-relative or root-relative.
    pub fn anchored(&self, cwd: &Path) -> Result<Self, TargetSyntaxError> {
        if !cwd.is_absolute() {
            return Err(TargetSyntaxError::RelativeWorkingDirectory);
        }
        let path = match self.primitive() {
            Primitive::Unix(path) | Primitive::File(path) | Primitive::Fifo(path, _) => path,
            Primitive::Tcp(_) | Primitive::Stdin(_) | Primitive::Echo => {
                return Ok(TargetSpec::clone(self));
            }
        };
        let native_path = Path::new(path);
        if native_path.is_absolute() {
            return Ok(TargetSpec::clone(self));
        }
        // Non-drive Windows prefixes have an implicit root. The remaining rootless drive spelling
        // must also be refused: resolving it would require mutable per-drive working-directory state.
        #[cfg(windows)]
        if native_path.has_root()
            || matches!(path.as_bytes(), [drive, b':', ..] if drive.is_ascii_alphabetic())
        {
            return Err(TargetSyntaxError::UnsupportedPathAnchoring);
        }
        let cwd = cwd.to_str().ok_or(TargetSyntaxError::PathEncoding)?;
        // Verbatim Windows paths recognize only backslashes as separators. Inspect the raw suffix,
        // never reconstruct components or use Path::join, which normalizes dots under verbatim cwd.
        #[cfg(windows)]
        let has_separator =
            cwd.ends_with('\\') || (!cwd.starts_with(r"\\?\") && cwd.ends_with('/'));
        #[cfg(not(windows))]
        let has_separator = cwd.ends_with(std::path::MAIN_SEPARATOR);
        let separator = if has_separator {
            ""
        } else {
            std::path::MAIN_SEPARATOR_STR
        };
        // Every path scheme has a five-byte prefix; only the parsed tail is anchored.
        format!("{}{cwd}{separator}{path}{}", &self.text[..5], self.suffix()).parse()
    }

    pub(super) fn primitive(&self) -> Primitive<'_> {
        let end = self.text.len() - self.suffix().len();
        match self.kind {
            Kind::Tcp => Primitive::Tcp(&self.text[..end]),
            Kind::Unix => Primitive::Unix(&self.text[5..end]),
            Kind::File => Primitive::File(&self.text[5..end]),
            Kind::Fifo(delivery) => Primitive::Fifo(&self.text[5..end], delivery),
            Kind::Stdin(delivery) => Primitive::Stdin(delivery),
            Kind::Echo => Primitive::Echo,
        }
    }

    fn suffix(&self) -> &'static str {
        match self.kind {
            Kind::Fifo(Delivery::Lossy) | Kind::Stdin(Delivery::Lossy) => "+lossy",
            _ => "",
        }
    }
}

impl FromStr for TargetSpec {
    type Err = TargetSyntaxError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Strip only the final suffix, so preceding suffix text remains part of the path.
        let (body, delivery) = match text.strip_suffix("+lossy") {
            Some(body) => (body, Delivery::Lossy),
            None => (text, Delivery::Reliable),
        };
        let (scheme, rest) = body
            .split_once(':')
            .ok_or(TargetSyntaxError::MissingScheme)?;
        if delivery == Delivery::Lossy && !matches!(scheme, "fifo" | "stdin") {
            return Err(TargetSyntaxError::UnsupportedLossy);
        }
        let kind = match scheme {
            "tcp" | "unix" => match Endpoint::from_str(body)? {
                Endpoint::Tcp => Kind::Tcp,
                Endpoint::Unix => Kind::Unix,
            },
            "file" | "fifo" => {
                if rest.is_empty() {
                    return Err(TargetSyntaxError::MissingPath);
                }
                if scheme == "file" {
                    Kind::File
                } else {
                    Kind::Fifo(delivery)
                }
            }
            "stdin" | "echo" => {
                if !rest.is_empty() {
                    return Err(TargetSyntaxError::UnexpectedArgument);
                }
                if scheme == "stdin" {
                    Kind::Stdin(delivery)
                } else {
                    Kind::Echo
                }
            }
            _ => return Err(TargetSyntaxError::UnknownScheme),
        };
        Ok(Self {
            text: text.to_owned(),
            kind,
        })
    }
}

impl PartialEq for TargetSpec {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for TargetSpec {}

/// A target syntax or path-anchoring error.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSyntaxError {
    /// target has no scheme
    #[error("target has no scheme")]
    MissingScheme,
    /// unknown target scheme
    #[error("unknown target scheme")]
    UnknownScheme,
    /// target takes no argument
    #[error("target takes no argument")]
    UnexpectedArgument,
    /// target needs a path
    #[error("target needs a path")]
    MissingPath,
    /// invalid local endpoint; expected `tcp:<host>:<port>` or `unix:<path>`
    #[error("invalid local endpoint; expected tcp:<host>:<port> or unix:<path>")]
    InvalidEndpoint,
    /// lossy mode is not supported for this target
    #[error("lossy mode is not supported for this target")]
    UnsupportedLossy,
    /// target path is not UTF-8
    #[error("target path is not UTF-8")]
    PathEncoding,
    /// working directory is not absolute
    #[error("working directory is not absolute")]
    RelativeWorkingDirectory,
    /// A drive-relative or root-relative Windows path cannot be anchored.
    #[error("cannot anchor a drive-relative or root-relative Windows path")]
    UnsupportedPathAnchoring,
}

/// A target-binding error.
#[derive(thiserror::Error, Debug)]
pub enum TargetError {
    /// service name is already defined
    #[error("service name is already defined")]
    AlreadyDefined,
    /// Backend preparation failed.
    #[error(transparent)]
    Preparation(#[from] eyre::Report),
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Tcp,
    Unix,
    File,
    Fifo(Delivery),
    Stdin(Delivery),
    Echo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Delivery {
    Reliable,
    Lossy,
}

pub(super) enum Primitive<'a> {
    Tcp(&'a str),
    Unix(&'a str),
    File(&'a str),
    Fifo(&'a str, Delivery),
    Stdin(Delivery),
    Echo,
}

pub(super) enum Endpoint {
    Tcp,
    Unix,
}

impl FromStr for Endpoint {
    type Err = TargetSyntaxError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.split_once(':') {
            // Right-splitting retains colons in a host. Host resolution and stricter socket syntax
            // belong to dialing, not to this grammar.
            Some(("tcp", rest))
                if rest.rsplit_once(':').is_some_and(|(host, port)| {
                    !host.is_empty() && port.parse::<u16>().is_ok()
                }) =>
            {
                Ok(Self::Tcp)
            }
            // Forward endpoints do not interpret a target's lossy suffix.
            Some(("unix", path)) if !path.is_empty() => Ok(Self::Unix),
            _ => Err(TargetSyntaxError::InvalidEndpoint),
        }
    }
}

#[cfg(test)]
#[path = "target_spec_tests.rs"]
mod target_spec_tests;
