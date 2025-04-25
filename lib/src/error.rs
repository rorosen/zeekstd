use zstd_safe::{ErrorCode, get_error_name, zstd_sys::ZSTD_ErrorCode};

/// A `Result` alias where the `Err` case is `zeekstd::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// The errors that may occur when working with this crate.
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    pub fn other<E>(err: E) -> Self
    where
        E: Into<Box<dyn core::error::Error + Send + Sync>>,
    {
        Self {
            kind: Kind::Other(err.into()),
        }
    }

    /// Returns true if the error is of type "Other".
    pub fn is_other(&self) -> bool {
        matches!(self.kind, Kind::Other(_))
    }

    pub(crate) fn offset_out_of_range() -> Self {
        Self {
            kind: Kind::OffsetOutOfRange,
        }
    }

    /// Returns true if the error is related to an offset that is out of range.
    pub fn is_offset_out_of_range(&self) -> bool {
        matches!(self.kind, Kind::OffsetOutOfRange)
    }

    pub(crate) fn write_in_progress() -> Self {
        Self {
            kind: Kind::WriteInProgress,
        }
    }

    /// Returns true if the error is related to a write in progress.
    pub fn is_write_in_progress(&self) -> bool {
        matches!(self.kind, Kind::WriteInProgress)
    }

    pub(crate) fn missing_checksum() -> Self {
        Self {
            kind: Kind::MissingChecksum,
        }
    }

    /// Returns true if the error is related to a missing checksum that is required.
    pub fn is_missing_checksum(&self) -> bool {
        matches!(self.kind, Kind::MissingChecksum)
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
        // TODO: Using usize for this doesn't seem right
        let wrapped = 0_usize.wrapping_sub(code as usize);
        Self {
            kind: Kind::Zstd(wrapped),
        }
    }

    /// Returns true if the error origins from the zstd library.
    pub fn is_zstd(&self) -> bool {
        matches!(self.kind, Kind::Zstd(_))
    }

    pub(crate) fn zstd_create(msg: &'static str) -> Self {
        Self {
            kind: Kind::ZstdCreate(msg),
        }
    }

    /// Returns true if the error is related to a failed creation of a zstd type.
    pub fn is_zstd_create(&self) -> bool {
        matches!(self.kind, Kind::ZstdCreate(_))
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            Kind::Other(err) => write!(f, "{err}"),
            Kind::NumberConversionFailed(err) => write!(f, "number conversion failed: {err}"),
            Kind::OffsetOutOfRange => f.write_str("offset out of range"),
            Kind::WriteInProgress => f.write_str("not supported when writing"),
            Kind::FrameIndexTooLarge => f.write_str("frame index too large"),
            Kind::IO(err) => write!(f, "io error: {err}"),
            Kind::MissingChecksum => f.write_str("checksum is required"),
            Kind::ZstdCreate(t) => write!(f, "failed to create zstd type {t:?}"),
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
    /// Action not supported when writing.
    WriteInProgress,
    /// The passed frame index is too large.
    FrameIndexTooLarge,
    /// IO error.
    IO(std::io::Error),
    /// A required checksum is missing.
    MissingChecksum,
    /// Failed to create zstd type.
    ZstdCreate(&'static str),
    /// An error from the zstd library.
    Zstd(ErrorCode),
}

impl core::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(arg0) => f.debug_tuple("Other").field(arg0).finish(),
            Self::NumberConversionFailed(arg0) => {
                f.debug_tuple("NumberConversionFailed").field(arg0).finish()
            }
            Self::OffsetOutOfRange => write!(f, "OffsetOutOfRange"),
            Self::WriteInProgress => write!(f, "WriteInProgress"),
            Self::FrameIndexTooLarge => write!(f, "FrameIndexTooLarge"),
            Self::IO(arg0) => f.debug_tuple("IO").field(arg0).finish(),
            Self::MissingChecksum => write!(f, "MissingChecksum"),
            Self::ZstdCreate(arg0) => f.debug_tuple("ZstdCreate").field(arg0).finish(),
            Self::Zstd(c) => write!(f, "{}; code {}", zstd_safe::get_error_name(*c), c),
        }
    }
}
