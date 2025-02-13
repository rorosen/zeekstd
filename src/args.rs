use std::{num::ParseIntError, path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};
use zstd_safe::CompressionLevel;

#[derive(Debug, Clone)]
pub struct DecompressPosition(u64);

impl DecompressPosition {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl FromStr for DecompressPosition {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Start" | "start" => Ok(Self(0)),
            "End" | "end" => Ok(Self(u64::MAX)),
            _ => Ok(Self(s.parse()?)),
        }
    }
}

#[derive(Debug, Subcommand)]
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

    /// The frame size at which to start a new seekable frame.
    #[arg(long, default_value_t = 8192)]
    pub max_frame_size: u32,

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
