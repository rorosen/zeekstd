use zstd_safe::{ErrorCode, get_error_name, zstd_sys::ZSTD_ErrorCode};

/// A `Result` alias where the `Err` case is `zeekstd::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// The errors that may occur when working with this crate.
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
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

    pub(crate) fn buffer_too_small() -> Self {
        Self {
            kind: Kind::BufferTooSmall,
        }
    }

    /// Returns true if the error is related to a buffer that is too small to make progress.
    pub fn is_buffer_too_small(&self) -> bool {
        matches!(self.kind, Kind::BufferTooSmall)
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

    pub(crate) fn frame_size_too_large() -> Self {
        Self {
            kind: Kind::FrameSizeTooLarge,
        }
    }

    /// Returns true if the error is related to a frame size that is too large.
    pub fn is_frame_size_too_large(&self) -> bool {
        matches!(self.kind, Kind::FrameSizeTooLarge)
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
            Kind::NumberConversionFailed(err) => write!(f, "number conversion failed: {err}"),
            Kind::OffsetOutOfRange => f.write_str("offset out of range"),
            Kind::WriteInProgress => f.write_str("not supported when writing"),
            Kind::BufferTooSmall => f.write_str("buffer too small to make progress"),
            Kind::FrameIndexTooLarge => f.write_str("frame index too large"),
            Kind::FrameSizeTooLarge => f.write_str("frame size too large"),
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
    /// Out of range integral type conversion attempted
    NumberConversionFailed(core::num::TryFromIntError),
    /// The desired offset is out of range.
    OffsetOutOfRange,
    /// Action not supported when writing.
    WriteInProgress,
    /// Buffer too small to make progress.
    BufferTooSmall,
    /// The passed frame index is too large.
    FrameIndexTooLarge,
    /// The desired frame size is too large.
    FrameSizeTooLarge,
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
            Self::NumberConversionFailed(arg0) => {
                f.debug_tuple("NumberConversionFailed").field(arg0).finish()
            }
            Self::OffsetOutOfRange => write!(f, "OffsetOutOfRange"),
            Self::WriteInProgress => write!(f, "SerializeInProgress"),
            Self::BufferTooSmall => write!(f, "BufferTooSmall"),
            Self::FrameIndexTooLarge => write!(f, "FrameIndexTooLarge"),
            Self::FrameSizeTooLarge => write!(f, "FrameSizeTooLarge"),
            Self::IO(arg0) => f.debug_tuple("IO").field(arg0).finish(),
            Self::MissingChecksum => write!(f, "MissingChecksum"),
            Self::ZstdCreate(arg0) => f.debug_tuple("Create").field(arg0).finish(),
            Self::Zstd(c) => write!(f, "{}; code {}", zstd_safe::get_error_name(*c), c),
        }
    }
}
