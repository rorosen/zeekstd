use std::{path::PathBuf, str::FromStr};

use anyhow::bail;
use clap::{Parser, Subcommand};
use zstd_safe::CompressionLevel;

#[derive(Debug, Clone)]
pub struct ByteValue(u64);

impl ByteValue {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }
}

impl FromStr for ByteValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, unit): (String, String) = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .partition(|c| c.is_ascii_digit());
        let value: u64 = value.parse()?;

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
pub struct DecompressPosition(u64);

impl DecompressPosition {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<ByteValue> for DecompressPosition {
    fn from(value: ByteValue) -> Self {
        Self(value.as_u64())
    }
}

impl FromStr for DecompressPosition {
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

#[derive(Debug, Subcommand)]
#[command(arg_required_else_help(true))]
pub enum CommandArgs {
    /// Compress (default, alias c) INPUT_FILE; reads from STDIN if INPUT_FILE is `-` or not provided
    #[clap(alias = "c")]
    Compress(CompressArgs),
    /// Decompress (alias d) INPUT_FILE
    #[clap(alias = "d")]
    Decompress(DecompressArgs),
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
    #[arg(long, default_value = "8192")]
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
    /// The decompressed position where decompression starts. Accepts the special values
    /// 'start' and 'end'.
    #[arg(long, group = "start", default_value = "start")]
    pub from: DecompressPosition,

    /// The frame number at which decompression starts.
    #[arg(long, group = "start")]
    pub from_frame: Option<u32>,

    /// The decompressed position where decompression ends. Accepts the special values
    /// 'start' and 'end'.
    #[arg(long, group = "end", default_value = "end")]
    pub to: DecompressPosition,

    /// The frame number at which decompression ends (inclusive).
    #[arg(long, group = "end")]
    pub to_frame: Option<u32>,

    /// Size of the intermediate decompression buffer.
    #[arg(long, default_value_t = 8192)]
    pub buffer_size: usize,

    /// Input file.
    pub input_file: PathBuf,

    /// Write data to the specified file.
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,
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
        for input in ["10G", "10 G", "10 gib", "10   gib"] {
            let result = ByteValue::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 10 * 1024 * 1024 * 1024);
        }
    }

    #[test]
    fn test_byte_value_from_str_valid_tib() {
        for input in ["10T", "10 T", "10 tib", "10   tib"] {
            let result = ByteValue::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 10 * 1024 * 1024 * 1024 * 1024);
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
            let result = DecompressPosition::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, 0);
        }
    }

    #[test]
    fn decompress_position_end() {
        for input in ["end", "End", "eND", "END"] {
            let result = DecompressPosition::from_str(input);
            assert!(result.is_ok());
            let parsed_value = result.unwrap();
            assert_eq!(parsed_value.0, u64::MAX);
        }
    }
}
