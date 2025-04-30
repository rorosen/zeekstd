use anyhow::Result;
use args::{CliFlags, CompressArgs};
use clap::Parser;
use command::Command;

mod args;
mod command;
mod compress;
mod decompress;

fn highbit_64(mut v: u64) -> u32 {
    let mut count = 0;
    v += 1024;
    v >>= 1;
    while v > 0 {
        v >>= 1;
        count += 1;
    }

    count
}

/// Compress and decompress data using the Zstandard Seekable Format.
#[derive(Debug, Parser)]
#[command(version, about)]
#[clap(args_conflicts_with_subcommands = true)]
struct Cli {
    #[clap(flatten)]
    flags: CliFlags,

    #[clap(subcommand)]
    command: Option<Command>,

    #[clap(flatten)]
    compress_args: CompressArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    cli.command
        .unwrap_or(Command::Compress(cli.compress_args))
        .run(cli.flags)
}
