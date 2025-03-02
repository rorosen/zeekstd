use std::{
    fs::{self, File},
    io::{self, IsTerminal, Read, Stdout, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use args::{CommandArgs, DecompressPosition};
use bar::Bar;
use compress::Compressor;
use decompress::Decompressor;
use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};

pub mod args;
mod bar;
mod compress;
mod decompress;
#[cfg(test)]
mod tests;

pub struct Operation {
    reader: Box<dyn Read>,
    writer: Writer,
}

enum Writer {
    Compress(Compressor<OutWriter>),
    Decompress(OutWriter),
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Writer::Compress(compressor) => compressor.write(buf),
            Writer::Decompress(out_writer) => out_writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Writer::Compress(compressor) => compressor.flush(),
            Writer::Decompress(out_writer) => out_writer.flush(),
        }
    }
}

impl Operation {
    pub fn new(args: CommandArgs, out: OutWriter) -> Result<Self> {
        match args {
            CommandArgs::Compress(cargs) => {
                let compressor = Compressor::new(&cargs, out)?;
                let reader: Box<dyn Read> = match cargs.input_file.as_os_str().to_str() {
                    Some("-") => Box::new(io::stdin()),
                    _ => Box::new(
                        File::open(&cargs.input_file).context("Failed to open input file")?,
                    ),
                };

                Ok(Self {
                    reader,
                    writer: Writer::Compress(compressor),
                })
            }
            CommandArgs::Decompress(dargs) => {
                let file = File::open(&dargs.input_file).context("Failed to open input file")?;
                let decompressor = Decompressor::new(Box::new(file), dargs)?;

                Ok(Self {
                    reader: Box::new(decompressor),
                    writer: Writer::Decompress(out),
                })
            }
        }
    }

    pub fn run(mut self, with_bar: bool, input_len: Option<u64>) -> Result<()> {
        let bar = with_bar.then(|| Bar::new(input_len));

        let res = if let Some(bar) = bar {
            io::copy(&mut bar.as_reader(self.reader), &mut self.writer)
        } else {
            io::copy(&mut self.reader, &mut self.writer)
        };

        let written = res.context("Failed to run operation")?;
        eprintln!("{written} bytes");

        if let Writer::Compress(mut compressor) = self.writer {
            compressor.end_stream()?;
        }

        Ok(())
    }
}

pub enum OutWriter {
    Stdout(Stdout),
    File { file: File, path: PathBuf },
}

impl OutWriter {
    pub fn new(
        path: Option<PathBuf>,
        force: bool,
        quiet: bool,
        is_input_stdin: bool,
    ) -> Result<Self> {
        match path {
            Some(path) => {
                if !force && path.exists() {
                    if quiet || is_input_stdin {
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
                let file = File::create(&path).context("Failed to create output file")?;

                Ok(Self::File { file, path })
            }
            None => {
                let stdout = io::stdout();
                if !force && stdout.is_terminal() {
                    bail!("stdout is a terminal, aborting");
                }

                Ok(Self::Stdout(stdout))
            }
        }
    }

    fn into_out_path(self) -> Option<PathBuf> {
        match self {
            OutWriter::Stdout(_) => None,
            OutWriter::File { path, .. } => Some(path),
        }
    }
}

impl Write for OutWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutWriter::Stdout(stdout) => stdout.write(buf),
            OutWriter::File { file, .. } => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutWriter::Stdout(stdout) => stdout.flush(),
            OutWriter::File { file, .. } => file.flush(),
        }
    }
}
