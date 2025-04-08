use std::fmt::Display;

use zstd_safe::{ErrorCode, get_error_name, zstd_sys::ZSTD_ErrorCode};

/// A `Result` alias where the `Err` case is `zeekstd::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// The errors that may occur when working with this crate.
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    pub(crate) fn missing_checksum() -> Self {
        Self {
            kind: Kind::MissingChecksum,
        }
    }

    pub(crate) fn frame_index_too_large() -> Self {
        Self {
            kind: Kind::FrameIndexTooLarge,
        }
    }

    pub(crate) fn zstd(code: ZSTD_ErrorCode) -> Self {
        let wrapped = 0_usize.wrapping_sub(code as usize);
        Self {
            kind: Kind::Zstd(wrapped),
        }
    }

    pub(crate) fn zstd_create(msg: &'static str) -> Self {
        Self {
            kind: Kind::Create(msg),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            Kind::FrameIndexTooLarge => f.write_str("frame index too large"),
            Kind::IO(err) => write!(f, "io error: {err}"),
            Kind::MissingChecksum => f.write_str("checksum is required"),
            Kind::Create(t) => write!(f, "failed to create {t:?}"),
            Kind::Zstd(code) => f.write_str(get_error_name(*code)),
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

#[derive(Debug)]
enum Kind {
    /// The passed frame index is too large.
    FrameIndexTooLarge,
    /// IO error.
    IO(std::io::Error),
    /// A required checksum is missing.
    MissingChecksum,
    /// Failed to create zstd type.
    Create(&'static str),
    /// An error from the zstd library.
    Zstd(ErrorCode),
}
