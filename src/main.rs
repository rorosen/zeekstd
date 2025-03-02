use std::io::{self, Write};

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::HumanBytes;
use zeekstd::{
    args::{CommandArgs, CompressArgs},
    Input, Output,
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

    /// Do not show the progress counter.
    #[arg(long, action, global = true)]
    no_progress: bool,

    #[clap(subcommand)]
    command_args: Option<CommandArgs>,

    #[clap(flatten)]
    compress_args: CompressArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let command_args = cli
        .command_args
        .unwrap_or(CommandArgs::Compress(cli.compress_args));
    let mut input = Input::new(&command_args)?;
    let mut output = Output::new(&command_args, cli.force, cli.quiet, cli.stdout)?;

    if !cli.quiet && !cli.stdout && !cli.no_progress {
        input.with_progress(command_args.input_len());
    }

    io::copy(&mut input, &mut output)?;
    output.flush().context("Failed to flush output")?;

    if !cli.quiet && !cli.stdout {
        let in_path = command_args.in_path().unwrap_or("STDIN");
        let bytes_read = input.bytes_read();

        match command_args {
            CommandArgs::Compress(_) => {
                let bytes_written = output.bytes_written();

                eprintln!(
                    "{in_path} : {ratio:.2}% ( {read} => {written}, {output_path})",
                    ratio = 100. / bytes_read as f64 * bytes_written as f64,
                    read = HumanBytes(bytes_read),
                    written = HumanBytes(output.bytes_written()),
                    output_path = command_args
                        .out_path(cli.stdout)
                        .as_ref()
                        .and_then(|o| o.as_os_str().to_str())
                        .unwrap_or("STDOUT")
                )
            }
            CommandArgs::Decompress(_) => eprintln!("{in_path} : {}", HumanBytes(bytes_read)),
        }
    }

    Ok(())
}
