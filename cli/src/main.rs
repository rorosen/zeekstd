use std::io::{self};

use anyhow::{Context, Result};
use args::CompressArgs;
use clap::Parser;
use command::Command;

mod args;
mod command;

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

    /// Do not show the progress counter.
    #[arg(long, action, global = true)]
    no_progress: bool,

    #[clap(subcommand)]
    command: Option<Command>,

    #[clap(flatten)]
    compress_args: CompressArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Compress(cli.compress_args));
    let mut input = command.input()?;
    let mut output = command.output(cli.force, cli.quiet, cli.stdout)?;

    let bytes_written = if matches!(command, Command::Compress(_) | Command::Decompress(_)) {
        // Whether to show the progress counter
        if !cli.quiet && !cli.stdout && !cli.no_progress {
            input.with_progress(command.input_len());
        }

        io::copy(&mut input, &mut output)?;
        output.finish().context("Failed to finish output")?
    } else {
        0
    };

    // Only print summary if not quiet
    if !cli.quiet {
        command.print_summary(input.bytes_read(), bytes_written, cli.stdout)?;
    }

    Ok(())
}
