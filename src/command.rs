use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, IsTerminal, Write},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use indicatif::HumanBytes;

use crate::{
    args::{CompressArgs, DecompressArgs, ListArgs},
    compress::Compressor,
    Input, InputReader, Output,
};

#[derive(Debug, Subcommand)]
#[command(arg_required_else_help(true))]
pub enum Command {
    /// Compress INPUT_FILE (default); reads from STDIN if INPUT_FILE is `-` or not provided
    #[clap(alias = "c")]
    Compress(CompressArgs),
    /// Decompress INPUT_FILE
    #[clap(alias = "d")]
    Decompress(DecompressArgs),
    /// Print information about seekable Zstandard-compressed files
    #[clap(alias = "l")]
    List(ListArgs),
}

impl Command {
    pub fn is_input_stdin(&self) -> bool {
        self.input_file_str() == Some("-")
    }

    pub fn input_file(&self) -> &Path {
        match self {
            Command::Compress(CompressArgs { input_file, .. })
            | Command::Decompress(DecompressArgs { input_file, .. })
            | Command::List(ListArgs { input_file, .. }) => input_file,
        }
    }

    pub fn input_file_str(&self) -> Option<&str> {
        self.input_file().as_os_str().to_str()
    }

    pub fn input_len(&self) -> Option<u64> {
        if self.is_input_stdin() {
            return None;
        }

        fs::metadata(self.input_file()).map(|m| m.len()).ok()
    }

    pub fn out_path(&self, stdout: bool) -> Option<PathBuf> {
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

        if stdout {
            return None;
        }

        match &self {
            Command::Compress(CompressArgs {
                input_file,
                output_file,
                ..
            }) => output_file
                .clone()
                .or_else(|| determine_out_path(input_file)),
            Command::Decompress(DecompressArgs {
                input_file,
                output_file,
                ..
            }) => output_file
                .clone()
                .or_else(|| Some(input_file.with_extension(""))),
            Command::List(_) => None,
        }
    }

    pub fn input(&self) -> Result<Input<'_>> {
        let reader = match self {
            Command::Compress(ref args) => match args.input_file.as_os_str().to_str() {
                Some("-") => InputReader::new_stdin(),
                _ => InputReader::new_file(&args.input_file)?,
            },
            Command::Decompress(ref args) => InputReader::new_decompressor(args)?,
            Command::List(ref args) => InputReader::new_file(&args.input_file)?,
        };

        Ok(Input { bar: None, reader })
    }

    pub fn output(&self, force: bool, quiet: bool, stdout: bool) -> Result<Output> {
        let writer: Box<dyn Write> = match self.out_path(stdout) {
            Some(path) => {
                let meta = fs::metadata(&path).ok();
                if !force && path.exists() && !meta.is_some_and(|m| m.file_type().is_char_device())
                {
                    if quiet || self.is_input_stdin() {
                        bail!("{} already exists; not overwritten", path.display());
                    }

                    eprint!("{} already exists; overwrite (y/n) ? ", path.display());
                    io::stderr().flush()?;
                    let mut buf = String::new();
                    io::stdin()
                        .read_line(&mut buf)
                        .context("Failed to read stdin")?;
                    if buf.trim_end() != "y" {
                        bail!("{} already exists", path.display());
                    }
                }
                let file = File::create(path).context("Failed to create output file")?;

                Box::new(file)
            }
            None => {
                let stdout = io::stdout();
                if !force && stdout.is_terminal() {
                    bail!("stdout is a terminal, aborting");
                }

                Box::new(stdout)
            }
        };

        if let Self::Compress(ref cargs) = self {
            let compressor = Compressor::new(cargs, writer)?;
            Ok(Output::Compressor(compressor))
        } else {
            Ok(Output::Writer {
                writer,
                bytes_written: 0,
            })
        }
    }

    pub fn print_summary(&self, bytes_read: u64, bytes_written: u64, stdout: bool) {
        let input_path = match self.input_file_str() {
            Some("-") => "STDIN",
            Some(path) => path,
            None => "",
        };

        match self {
            Self::Compress(_) => {
                eprintln!(
                    "{input_path} : {ratio:.2}% ( {read} => {written}, {output_path})",
                    ratio = 100. / bytes_read as f64 * bytes_written as f64,
                    read = HumanBytes(bytes_read),
                    written = HumanBytes(bytes_written),
                    output_path = self
                        .out_path(stdout)
                        .as_ref()
                        .and_then(|o| o.as_os_str().to_str())
                        .unwrap_or("STDOUT")
                )
            }
            Self::Decompress(_) => {
                eprintln!("{input_path} : {}", HumanBytes(bytes_read))
            }
            Self::List(_) => {
                unreachable!("The program never gets here when command is list")
            }
        }
    }
}
