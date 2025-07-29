use std::{fs, path::PathBuf, str::FromStr};

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use zeekstd::{CompressionLevel, SeekTable};

// 128 MiB
const MMAP_THRESHOLD: u64 = 0x0010_0000;

#[derive(Debug, Clone)]
pub struct ByteValue(u32);

impl ByteValue {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl FromStr for ByteValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const ERRMSG: &str = "Byte value too large";
        let value: String = s.chars().take_while(char::is_ascii_digit).collect();
        let unit: String = s[value.len()..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let value: u32 = value.parse()?;

        let value = match unit.as_str() {
            "B" | "" => value,
            "K" | "kib" => value.checked_mul(1024).context(ERRMSG)?,
            "M" | "mib" => value.checked_mul(1024 * 1024).context(ERRMSG)?,
            "G" | "gib" => value.checked_mul(1024 * 1024 * 1024).context(ERRMSG)?,
            _ => bail!("Unknown unit: {unit:?}"),
        };

        Ok(Self(value))
    }
}

#[derive(Debug, Clone)]
pub enum OffsetLimit {
    End,
    Value(u64),
}

impl From<ByteValue> for OffsetLimit {
    fn from(value: ByteValue) -> Self {
        Self::Value(value.0 as u64)
    }
}

impl FromStr for OffsetLimit {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let this = match s.to_lowercase().as_str() {
            "end" => Self::End,
            _ => Self::from(ByteValue::from_str(s)?),
        };

        Ok(this)
    }
}

#[derive(Debug, Clone)]
pub enum LastFrame {
    End,
    Index(u32),
}

impl FromStr for LastFrame {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let this = match s.to_lowercase().as_str() {
            "end" => Self::End,
            _ => Self::Index(u32::from_str(s)?),
        };

        Ok(this)
    }
}

#[derive(Debug, Parser, Clone)]
pub struct CliFlags {
    /// Suppress output. Ignored in list mode.
    #[arg(short, long, action, global = true)]
    pub quiet: bool,

    /// Disable human-readable formatting for all byte numbers.
    #[arg(short, long, action, global = true)]
    pub raw_bytes: bool,
}

impl CliFlags {
    pub fn progress_bar(&self, in_path: Option<&str>) -> Option<ProgressBar> {
        (!self.quiet).then(|| {
            let len = in_path.and_then(|p| fs::metadata(p).map(|m| m.len()).ok());
            ProgressBar::with_draw_target(len, ProgressDrawTarget::stderr_with_hz(5)).with_style(
                ProgressStyle::with_template("{binary_bytes} of {binary_total_bytes}")
                    .expect("Static template always works"),
            )
        })
    }
}

#[derive(Debug, Parser, Clone)]
pub struct CommonArgs {
    /// Disable output checks.
    #[arg(short, long, action, global = true)]
    pub force: bool,

    /// Write to STDOUT.
    #[arg(short = 'c', long, action, global = true)]
    pub stdout: bool,

    /// Do not show the progress counter.
    #[arg(long, action, global = true)]
    pub no_progress: bool,

    /// Force memory-mapping prefix (patch) files.
    #[arg(long, action, global = true)]
    pub mmap_prefix: bool,

    /// Force disable memory-mapping prefix (patch) files.
    #[arg(long, action, global = true)]
    pub no_mmap_prefix: bool,

    /// Path to the seek table file. If specified, implies the "Head" seek table format.
    #[arg(long, global = true)]
    pub seek_table_file: Option<PathBuf>,
}

impl CommonArgs {
    pub fn use_mmap(&self, prefix_len: Option<u64>) -> bool {
        if self.mmap_prefix {
            return true;
        }

        if self.no_mmap_prefix {
            return false;
        }

        prefix_len.is_some_and(|l| l >= MMAP_THRESHOLD)
    }
}

#[derive(Debug, ValueEnum, Clone)]
pub enum FrameSizePolicy {
    Compressed,
    Uncompressed,
}

#[derive(Debug, Parser, Clone)]
pub struct CompressArgs {
    #[clap(flatten)]
    pub common: CommonArgs,

    /// Desired compression level between 1 and 19. Lower numbers provide faster compression,
    /// higher numbers yield better compression ratios.
    #[arg(short = 'l', long, default_value_t = 3)]
    pub compression_level: CompressionLevel,

    /// Don't include frame checksums.
    #[arg(long, action)]
    pub no_checksum: bool,

    /// The frame size at which to start a new frame. Accepts the suffixes K (kib), M (mib) and G
    /// (gib).
    #[arg(long, default_value = "2M")]
    pub frame_size: ByteValue,

    /// Whether to apply the frame size to compressed or uncompressed size of the frame data.
    #[arg(long, default_value = "uncompressed")]
    pub frame_size_policy: FrameSizePolicy,

    /// Provide a reference point for Zstandard's diff engine.
    #[arg(long)]
    pub patch_from: Option<PathBuf>,

    /// Input file.
    #[arg(default_value = "-")]
    pub input_file: String,

    /// Write data to the specified file.
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,
}

impl CompressArgs {
    pub fn to_frame_size_policy(&self) -> zeekstd::FrameSizePolicy {
        match self.frame_size_policy {
            FrameSizePolicy::Compressed => {
                zeekstd::FrameSizePolicy::Compressed(self.frame_size.as_u32())
            }
            FrameSizePolicy::Uncompressed => {
                zeekstd::FrameSizePolicy::Uncompressed(self.frame_size.as_u32())
            }
        }
    }
}

#[derive(Debug, Parser, Clone)]
pub struct DecompressArgs {
    #[clap(flatten)]
    pub common: CommonArgs,

    /// The offset (of the uncompressed data) where decompression starts.
    #[arg(long, group = "start", default_value_t = 0)]
    pub from: u64,

    /// The frame number at which decompression starts.
    #[arg(long, group = "start")]
    pub from_frame: Option<u32>,

    /// The offset (of the decompressed data) where decompression ends.
    ///
    /// Accepts the special value 'end'.
    #[arg(long, group = "end", default_value = "end")]
    pub to: OffsetLimit,

    /// The frame number at which decompression ends (inclusive).
    ///
    /// Accepts special value 'last'.
    #[arg(long, group = "end")]
    pub to_frame: Option<LastFrame>,

    /// Provide a reference point for Zstandard's diff engine.
    #[arg(long)]
    pub patch_apply: Option<PathBuf>,

    /// Input file.
    pub input_file: String,

    /// Write data to the specified file.
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,
}

impl DecompressArgs {
    pub fn offset(&self, seek_table: &SeekTable) -> anyhow::Result<u64> {
        let offset = if let Some(index) = self.from_frame {
            seek_table.frame_start_decomp(index)?
        } else {
            self.from
        };

        Ok(offset)
    }

    pub fn offset_limit(&self, seek_table: &SeekTable) -> anyhow::Result<u64> {
        let limit = if let Some(end) = &self.to_frame {
            match end {
                LastFrame::End => seek_table.size_decomp(),
                LastFrame::Index(i) => seek_table.frame_end_decomp(*i)?,
            }
        } else {
            match self.to {
                OffsetLimit::End => seek_table.size_decomp(),
                OffsetLimit::Value(val) => val,
            }
        };

        Ok(limit)
    }
}

#[derive(Debug, ValueEnum, Clone)]
pub enum SeekTableFormat {
    Head,
    Foot,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// The frame number at which listing starts.
    #[arg(long)]
    pub from_frame: Option<u32>,

    /// The frame number at which listing ends (inclusive).
    ///
    /// Accepts special value 'last'.
    #[arg(long, group = "end")]
    pub to_frame: Option<LastFrame>,

    /// The number of frames to list.
    #[arg(long, group = "end")]
    pub num_frames: Option<u32>,

    /// Detailed listing of individual frames, implied when frame boundaries are specified.
    #[arg(short, long, action)]
    pub detail: bool,

    /// The format of the seek table.
    #[arg(long, default_value = "foot")]
    pub seek_table_format: SeekTableFormat,

    /// Input file.
    pub input_file: String,
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
    fn decompress_end_frame() {
        for input in ["end", "End", "eND", "END"] {
            let value = LastFrame::from_str(input).unwrap();
            assert!(matches!(value, LastFrame::End));
        }
    }
}
