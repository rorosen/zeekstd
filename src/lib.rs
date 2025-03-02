use std::{
    fs::File,
    io::{self, IsTerminal, Read, Stdin, Write},
    path::Path,
};

use anyhow::{bail, Context, Result};
use args::{CommandArgs, DecompressArgs};
use compress::Compressor;
use decompress::Decompressor;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

pub mod args;
mod compress;
mod decompress;
#[cfg(test)]
mod tests;

enum InputReader<'a> {
    Stdin { stdin: Stdin, bytes_read: u64 },
    File { file: File, bytes_read: u64 },
    Decompressor(Decompressor<'a, File>),
}

impl InputReader<'_> {
    fn new_stdin() -> Self {
        Self::Stdin {
            stdin: io::stdin(),
            bytes_read: 0,
        }
    }

    fn new_file(path: &Path) -> Result<Self> {
        let file = File::open(path).context("Failed to open input file")?;
        Ok(Self::File {
            file,
            bytes_read: 0,
        })
    }

    fn new_decompressor(args: &DecompressArgs) -> Result<Self> {
        let file = File::open(&args.input_file).context("Failed to open input file")?;
        let decompressor = Decompressor::new(file, args)?;

        Ok(Self::Decompressor(decompressor))
    }
}

pub struct Input<'a> {
    bar: Option<ProgressBar>,
    reader: InputReader<'a>,
}

impl Input<'_> {
    pub fn new(args: &CommandArgs) -> Result<Self> {
        let reader = match args {
            CommandArgs::Compress(ref cargs) => match cargs.input_file.as_os_str().to_str() {
                Some("-") => InputReader::new_stdin(),
                _ => InputReader::new_file(&cargs.input_file)?,
            },
            CommandArgs::Decompress(ref dargs) => InputReader::new_decompressor(dargs)?,
        };

        Ok(Self { bar: None, reader })
    }

    pub fn with_progress(&mut self, input_len: Option<u64>) {
        let bar = ProgressBar::with_draw_target(input_len, ProgressDrawTarget::stderr_with_hz(5))
            .with_style(
                ProgressStyle::with_template("{binary_bytes} of {binary_total_bytes}")
                    .expect("Static template always works"),
            );

        self.bar = Some(bar);
    }

    pub fn bytes_read(&self) -> u64 {
        match &self.reader {
            InputReader::Stdin { bytes_read, .. } => *bytes_read,
            InputReader::File { bytes_read, .. } => *bytes_read,
            InputReader::Decompressor(decompressor) => decompressor.bytes_read(),
        }
    }
}

impl Read for Input<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = match &mut self.reader {
            InputReader::Stdin {
                stdin: reader,
                bytes_read,
            } => {
                let n = reader.read(buf)?;
                *bytes_read += n as u64;
                n
            }
            InputReader::File {
                file: reader,
                bytes_read,
            } => {
                let n = reader.read(buf)?;
                *bytes_read += n as u64;
                n
            }
            InputReader::Decompressor(decompressor) => decompressor.read(buf)?,
        };

        if let Some(bar) = &self.bar {
            bar.inc(n as u64);
            if n == 0 {
                bar.finish_and_clear();
            }
        }

        Ok(n)
    }
}

pub enum Output {
    Writer {
        writer: Box<dyn Write>,
        bytes_written: u64,
    },
    Compressor(Compressor<Box<dyn Write>>),
}

impl Output {
    pub fn new(args: &CommandArgs, force: bool, quiet: bool, stdout: bool) -> Result<Self> {
        let writer: Box<dyn Write> = match args.out_path(stdout) {
            Some(path) => {
                if !force && path.exists() {
                    if quiet || args.is_input_stdin() {
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

        if let CommandArgs::Compress(ref cargs) = args {
            let compressor = Compressor::new(cargs, writer)?;
            Ok(Self::Compressor(compressor))
        } else {
            Ok(Self::Writer {
                writer,
                bytes_written: 0,
            })
        }
    }

    pub fn bytes_written(&self) -> u64 {
        match &self {
            Self::Writer { bytes_written, .. } => *bytes_written,
            Self::Compressor(compressor) => compressor.bytes_written(),
        }
    }
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = match self {
            Self::Writer {
                writer,
                bytes_written,
            } => {
                let n = writer.write(buf)?;
                *bytes_written += n as u64;
                n
            }
            Self::Compressor(compressor) => compressor.write(buf)?,
        };
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Writer { writer, .. } => writer.flush(),
            Self::Compressor(compressor) => compressor.flush(),
        }
    }
}
