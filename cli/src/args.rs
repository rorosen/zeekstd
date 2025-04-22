use std::{path::PathBuf, str::FromStr};

use anyhow::bail;
use clap::Parser;
use zeekstd::{CompressionLevel, SeekTable};

#[derive(Debug, Clone)]
pub struct ByteValue(u32);

impl ByteValue {
    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl FromStr for ByteValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, unit): (String, String) = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .partition(|c| c.is_ascii_digit());
        let value = value.parse()?;

        let value = match unit.as_str() {
            "" | "B" => value,
            "K" | "kib" => value * 1024,
            "M" | "mib" => value * 1024 * 1024,
            "G" | "gib" => value * 1024 * 1024 * 1024,
            "T" | "tib" => value * 1024 * 1024 * 1024 * 1024,
            _ => bail!("Unknown unit: {unit:?}"),
        };

        Ok(Self(value))
    }
}

#[derive(Debug, Clone)]
pub struct ByteOffset(u64);

impl ByteOffset {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<ByteValue> for ByteOffset {
    fn from(value: ByteValue) -> Self {
        Self(value.as_u64())
    }
}

impl FromStr for ByteOffset {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let this = match s.to_lowercase().as_str() {
            "start" => Self(0),
            "end" => Self(u64::MAX),
            _ => Self::from(ByteValue::from_str(s)?),
        };

        Ok(this)
    }
}

#[derive(Debug, Parser)]
pub struct CompressArgs {
    /// Desired compression level between 1 and 19. Lower numbers provide faster compression,
    /// higher numbers yield better compression ratios.
    #[arg(long, default_value_t = 3)]
    pub compression_level: CompressionLevel,

    /// Don't include frame checksums in the seek table.
    #[arg(long, action)]
    pub no_checksum: bool,

    /// The frame size at which to start a new seekable frame. Accepts the suffixes kib, mib, gib
    /// and tib.
    #[arg(long, default_value = "2M")]
    pub max_frame_size: ByteValue,

    /// Input file.
    #[arg(default_value = "-")]
    pub input_file: PathBuf,

    /// Write data to the specified file.
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct DecompressArgs {
    /// The offset (of the uncompressed data) where decompression starts. Accepts the special
    /// values 'start' and 'end'.
    #[arg(long, group = "start", default_value = "start")]
    pub from: ByteOffset,

    /// The frame number at which decompression starts.
    #[arg(long, group = "start")]
    pub from_frame: Option<u32>,

    /// The offset (of the decompressed data) where decompression ends. Accepts the special
    /// values 'start' and 'end'.
    #[arg(long, group = "end", default_value = "end")]
    pub to: ByteOffset,

    /// The frame number at which decompression ends (inclusive).
    #[arg(long, group = "end")]
    pub to_frame: Option<u32>,

    /// Input file.
    pub input_file: PathBuf,

    /// Write data to the specified file.
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// The offset (of the decompressed data) where listing starts. Accepts the special values
    /// 'start' and 'end'.
    #[arg(long, group = "start")]
    pub from: Option<ByteOffset>,

    /// The frame number at which listing starts.
    #[arg(long, group = "start")]
    pub from_frame: Option<u32>,

    /// The offset (of the decompressed data) where lisitng ends. Accepts the special values
    /// 'start' and 'end'.
    #[arg(long, group = "end")]
    pub to: Option<ByteOffset>,

    /// The frame number at which listing ends.
    #[arg(long, group = "end")]
    pub to_frame: Option<u32>,

    /// The number of frames that should be listed.
    #[arg(long, group = "end")]
    pub num_frames: Option<u32>,

    /// Detailed listing of individual frames, automatically implied when frame boundaries are
    /// provided.
    #[arg(short, long, action)]
    pub detail: bool,

    /// Print human readable byte values like 1KiB.
    #[arg(short = 'b', long, action)]
    pub human_bytes: bool,

    /// Input file.
    pub input_file: PathBuf,
}

impl ListArgs {
    pub fn start_frame(&self, seek_table: &SeekTable) -> Option<u32> {
        if self.from_frame.is_some() {
            self.from_frame
        } else {
            self.from
                .as_ref()
                .map(|offset| seek_table.frame_index_decomp(offset.as_u64()))
        }
    }

    pub fn end_frame(&self, seek_table: &SeekTable) -> Option<u32> {
        if self.to_frame.is_some() {
            self.to_frame
        } else if let Some(offset) = &self.to {
            Some(seek_table.frame_index_decomp(offset.as_u64()))
        } else {
            self.num_frames
                .map(|num| self.start_frame(seek_table).unwrap_or(0) + num)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_value_from_str_no_unit() {
        let input = "10";
        let result = ByteValue::from_str(input);
        assert!(result.is_ok());
        let parsed_value = result.unwrap();
        assert_eq!(parsed_value.0, 10);
    }

    #[test]
    fn test_byte_value_from_str_valid_b() {
        for input in ["10B", "10 B", "10   B"] {
            let result = ByteValue::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 10);
        }
    }

    #[test]
    fn test_byte_value_from_str_valid_kib() {
        for input in ["10K", "10 K", "10 kib", "10   kib"] {
            let result = ByteValue::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 10 * 1024);
        }
    }

    #[test]
    fn test_byte_value_from_str_valid_mib() {
        for input in ["10M", "10 M", "10 mib", "10   mib"] {
            let result = ByteValue::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 10 * 1024 * 1024);
        }
    }

    #[test]
    fn test_byte_value_from_str_valid_gib() {
        for input in ["2G", "2 G", "2 gib", "2   gib"] {
            let result = ByteValue::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 2 * 1024 * 1024 * 1024);
        }
    }

    #[test]
    fn test_byte_value_from_str_invalid_unit() {
        let input = "10 X";
        let result = ByteValue::from_str(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_byte_value_from_str_missing_value() {
        let input = " ";
        let result = ByteValue::from_str(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_byte_value_from_str_non_numeric_value() {
        let input = "abc B";
        let result = ByteValue::from_str(input);
        assert!(result.is_err());
    }

    #[test]
    fn decompress_position_start() {
        for input in ["start", "Start", "StARt", "START"] {
            let result = ByteOffset::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 0);
        }
    }

    #[test]
    fn decompress_position_end() {
        for input in ["end", "End", "eND", "END"] {
            let result = ByteOffset::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, u64::MAX);
        }
    }
}
