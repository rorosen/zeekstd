use alloc::boxed::Box;
use zstd_safe::{ErrorCode, get_error_name, zstd_sys::ZSTD_ErrorCode};

/// A `Result` alias where the `Err` case is `zeekstd::Error`.
pub type Result<T> = core::result::Result<T, Error>;

/// The errors that may occur when working with this crate.
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    /// A custom error.
    pub fn other<E>(err: E) -> Self
    where
        E: Into<Box<dyn core::error::Error + Send + Sync>>,
    {
        Self {
            kind: Kind::Other(err.into()),
        }
    }

    /// Returns true if the error cannot be categorized into any other kind.
    pub fn is_other(&self) -> bool {
        matches!(self.kind, Kind::Other(_))
    }

    /// Returns true if the error origins from a failed number conversion.
    pub fn is_number_conversion_failed(&self) -> bool {
        matches!(self.kind, Kind::NumberConversionFailed(_))
    }

    pub(crate) fn offset_out_of_range() -> Self {
        Self {
            kind: Kind::OffsetOutOfRange,
        }
    }

    /// Returns true if the error origins from an out of range offset.
    pub fn is_offset_out_of_range(&self) -> bool {
        matches!(self.kind, Kind::OffsetOutOfRange)
    }

    pub(crate) fn frame_index_too_large() -> Self {
        Self {
            kind: Kind::FrameIndexTooLarge,
        }
    }

    /// Returns true if the error is related to a frame index that is too large.
    pub fn is_frame_index_too_large(&self) -> bool {
        matches!(self.kind, Kind::FrameIndexTooLarge)
    }

    pub(crate) fn zstd(code: ZSTD_ErrorCode) -> Self {
        let wrapped = 0_usize.wrapping_sub(code as usize);
        Self {
            kind: Kind::Zstd(wrapped),
        }
    }

    /// Returns true if the error origins from an IO error.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn is_io(&self) -> bool {
        matches!(self.kind, Kind::IO(_))
    }

    /// Returns true if the error origins from the zstd library.
    pub fn is_zstd(&self) -> bool {
        matches!(self.kind, Kind::Zstd(_))
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.kind {
            Kind::Other(err) => write!(f, "{err}"),
            Kind::NumberConversionFailed(err) => write!(f, "number conversion failed: {err}"),
            Kind::OffsetOutOfRange => f.write_str("offset out of range"),
            Kind::FrameIndexTooLarge => f.write_str("frame index too large"),
            #[cfg(feature = "std")]
            Kind::IO(err) => write!(f, "io error: {err}"),
            Kind::Zstd(code) => f.write_str(get_error_name(*code)),
        }
    }
}

impl core::error::Error for Error {}

impl From<core::num::TryFromIntError> for Error {
    fn from(value: core::num::TryFromIntError) -> Self {
        Self {
            kind: Kind::NumberConversionFailed(value),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: Kind::IO(value),
        }
    }
}

impl From<ErrorCode> for Error {
    fn from(value: ErrorCode) -> Self {
        Self {
            kind: Kind::Zstd(value),
        }
    }
}

enum Kind {
    Other(Box<dyn core::error::Error + Send + Sync>),
    /// Out of range integral type conversion attempted
    NumberConversionFailed(core::num::TryFromIntError),
    /// The desired offset is out of range.
    OffsetOutOfRange,
    /// The passed frame index is too large.
    FrameIndexTooLarge,
    /// IO error.
    #[cfg(feature = "std")]
    IO(std::io::Error),
    /// An error from the zstd library.
    Zstd(ErrorCode),
}

impl core::fmt::Debug for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Other(arg0) => f.debug_tuple("Other").field(arg0).finish(),
            Self::NumberConversionFailed(arg0) => {
                f.debug_tuple("NumberConversionFailed").field(arg0).finish()
            }
            Self::OffsetOutOfRange => write!(f, "OffsetOutOfRange"),
            Self::FrameIndexTooLarge => write!(f, "FrameIndexTooLarge"),
            #[cfg(feature = "std")]
            Self::IO(arg0) => f.debug_tuple("IO").field(arg0).finish(),
            Self::Zstd(c) => write!(f, "{}; code {}", zstd_safe::get_error_name(*c), c),
        }
    }
}
