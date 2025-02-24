use std::{
    ffi::OsString,
    fs::{self},
    path::PathBuf,
};

use anyhow::Result;
use clap::Parser;
use zeekstd::{
    args::{CommandArgs, CompressArgs, DecompressArgs},
    OutWriter, Zeekstd,
};

/// Compress and decompress data using the Zstandard Seekable Format.
#[derive(Debug, Parser)]
#[command(version, about)]
#[clap(args_conflicts_with_subcommands = true)]
struct Cli {
    /// Disable output checks.
    #[arg(short, long, action, global = true)]
    force: bool,

    /// Suppress output.
    #[arg(short, long, action, global = true)]
    quiet: bool,

    /// Write to STDOUT.
    #[arg(short = 'c', long, action, global = true)]
    stdout: bool,

    #[clap(subcommand)]
    command_args: Option<CommandArgs>,

    #[clap(flatten)]
    compress_args: CompressArgs,
}

impl Cli {
    pub fn is_input_stdin(&self) -> bool {
        let input_file = match &self.command_args {
            Some(CommandArgs::Compress(CompressArgs { input_file, .. }))
            | Some(CommandArgs::Decompress(DecompressArgs { input_file, .. })) => input_file,
            None => &self.compress_args.input_file,
        };
        input_file.as_os_str().to_str() == Some("-")
    }

    fn input_len(&self) -> Option<u64> {
        let input_file = match &self.command_args {
            Some(CommandArgs::Compress(CompressArgs { input_file, .. })) => {
                if self.is_input_stdin() {
                    return None;
                }
                input_file
            }
            Some(CommandArgs::Decompress(DecompressArgs { input_file, .. })) => input_file,
            None => &self.compress_args.input_file,
        };

        fs::metadata(input_file).map(|m| m.len()).ok()
    }

    fn out_path(&self) -> Option<PathBuf> {
        let determine_out_path = |input_file: &PathBuf| {
            if self.is_input_stdin() {
                return None;
            }

            // TODO: Use `add_extension` when stable: https://github.com/rust-lang/rust/issues/127292
            let extension = input_file.extension().map_or_else(
                || OsString::from("zst"),
                |e| {
                    let mut ext = OsString::from(e);
                    ext.push(".zst");
                    ext
                },
            );

            Some(input_file.with_extension(extension))
        };

        if self.stdout {
            return None;
        }

        match &self.command_args {
            Some(CommandArgs::Compress(CompressArgs {
                input_file,
                output_file,
                ..
            })) => output_file
                .clone()
                .or_else(|| determine_out_path(input_file)),
            Some(CommandArgs::Decompress(DecompressArgs {
                input_file,
                output_file,
                ..
            })) => output_file
                .clone()
                .or_else(|| Some(input_file.with_extension(""))),
            None => self
                .compress_args
                .output_file
                .clone()
                .or_else(|| determine_out_path(&self.compress_args.input_file)),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let out_path = cli.out_path();
    let out_writer = OutWriter::new(out_path, cli.force, cli.quiet, cli.is_input_stdin())?;
    let input_len = cli.input_len();
    let command_args = cli
        .command_args
        .unwrap_or(CommandArgs::Compress(cli.compress_args));
    let mut zeekstd = Zeekstd::new(command_args, out_writer)?;
    if !cli.quiet && !cli.stdout {
        zeekstd.with_progress_bar(input_len);
    }

    zeekstd.run()
}
