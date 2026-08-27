//! A short human duration like `2h`, `30m`, `90s`, for capability expiry flags.

use core::str::FromStr;
use core::time::Duration;

/// A capability lifetime parsed from a suffixed number: `<n>s`, `<n>m`, `<n>h`, or `<n>d`.
///
/// A domain scalar so a flag like `--expires 2h` reaches the command as a real [`Duration`], not a
/// string the handler re-parses. parse-don't-validate: an unparseable or zero span never becomes a
/// `Lifetime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime(Duration);

impl Lifetime {
    /// The lifetime as a [`Duration`].
    pub fn duration(self) -> Duration {
        let Self(duration) = self;
        duration
    }
}

impl FromStr for Lifetime {
    type Err = LifetimeParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (digits, unit) = text.split_at(text.len().saturating_sub(1));
        let seconds_per = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 60 * 60,
            "d" => 24 * 60 * 60,
            _ => return Err(LifetimeParseError::BadUnit),
        };
        let count = digits
            .parse::<u64>()
            .map_err(LifetimeParseError::BadNumber)?;
        let seconds = count
            .checked_mul(seconds_per)
            .ok_or(LifetimeParseError::TooLong)?;
        if seconds == 0 {
            return Err(LifetimeParseError::Zero);
        }
        Ok(Self(Duration::from_secs(seconds)))
    }
}

/// Why a string could not be parsed into a [`Lifetime`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LifetimeParseError {
    /// The unit suffix was not one of `s`, `m`, `h`, `d`.
    #[error("duration must end in s, m, h, or d (e.g. 2h)")]
    BadUnit,
    /// The numeric part was not a non-negative integer.
    #[error("duration is not a number")]
    BadNumber(#[source] core::num::ParseIntError),
    /// The duration overflowed.
    #[error("duration is too long")]
    TooLong,
    /// The duration was zero.
    #[error("duration must be greater than zero")]
    Zero,
}
