use std::io::{self, Write};

use anyhow::{Context, Result};
use args::CompressArgs;
use clap::Parser;
use command::Command;

mod args;
mod command;
mod compress;
mod decompress;
#[cfg(test)]
mod tests;

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

impl Cli {
    fn show_progress(&self) -> bool {
        !self.quiet && !self.stdout && !self.no_progress
    }

    fn print_summary(&self) -> bool {
        !self.quiet && !self.stdout
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let show_progress = cli.show_progress();
    let print_summary = cli.print_summary();
    let command = cli.command.unwrap_or(Command::Compress(cli.compress_args));

    let mut input = command.input()?;
    let mut output = command.output(cli.force, cli.quiet, cli.stdout)?;

    if matches!(command, Command::Compress(_) | Command::Decompress(_)) {
        if show_progress {
            input.with_progress(command.input_len());
        }

        io::copy(&mut input, &mut output)?;
        output.flush().context("Failed to flush output")?;
    }

    if print_summary {
        command.print_summary(input.bytes_read(), output.bytes_written(), cli.stdout)?;
    }

    Ok(())
}
