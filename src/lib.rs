use std::{
    fs::{self, File},
    io::{self, IsTerminal, Read, Stdout, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use args::{CommandArgs, DecompressPosition};
use compress::Compressor;
use decompress::Decompressor;
use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};

pub mod args;
mod compress;
mod decompress;
#[cfg(test)]
mod tests;

pub enum Mode<'a> {
    Compress {
        compressor: Compressor,
        input: Box<dyn Read>,
    },
    Decompress {
        decompressor: Decompressor<'a, File>,
        from: DecompressPosition,
        from_frame: Option<u32>,
        to: DecompressPosition,
        to_frame: Option<u32>,
    },
}

impl Mode<'_> {
    fn as_str(&self) -> &'static str {
        match self {
            Mode::Compress { .. } => "Compression",
            Mode::Decompress { .. } => "Decompression",
        }
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

pub struct Zeekstd<'a> {
    mode: Mode<'a>,
    in_path: Option<PathBuf>,
    output: OutWriter,
    progress_bar: Option<ProgressBar>,
}

impl Zeekstd<'_> {
    pub fn new(args: CommandArgs, output: OutWriter) -> Result<Self> {
        match args {
            CommandArgs::Compress(cargs) => {
                let mut in_path = None;
                let compressor = Compressor::new(
                    cargs.compression_level,
                    !cargs.no_checksum,
                    cargs.max_frame_size,
                )?;
                let input: Box<dyn Read> = match cargs.input_file.as_os_str().to_str() {
                    Some("-") => Box::new(io::stdin()),
                    _ => {
                        let input = Box::new(
                            File::open(&cargs.input_file).context("Failed to open input file")?,
                        );
                        in_path = Some(cargs.input_file);
                        input
                    }
                };
                let mode = Mode::Compress {
                    compressor,
                    input: Box::new(input),
                };
                Ok(Self {
                    mode,
                    in_path,
                    output,
                    progress_bar: None,
                })
            }
            CommandArgs::Decompress(dargs) => {
                let file = File::open(&dargs.input_file).context("Failed to open input file")?;
                let decompressor = Decompressor::new(Box::new(file))?;
                let mode = Mode::Decompress {
                    decompressor,
                    from: dargs.from,
                    from_frame: dargs.from_frame,
                    to: dargs.to,
                    to_frame: dargs.to_frame,
                };
                Ok(Self {
                    mode,
                    in_path: Some(dargs.input_file),
                    output,
                    progress_bar: None,
                })
            }
        }
    }

    pub fn with_progress_bar(&mut self, input_len: Option<u64>) {
        let bar = ProgressBar::with_draw_target(input_len, ProgressDrawTarget::stderr_with_hz(5))
            .with_style(
                ProgressStyle::with_template("Read {binary_bytes} of {binary_total_bytes}")
                    .expect("Static template always works"),
            );
        self.progress_bar = Some(bar);
    }

    pub fn run(mut self) -> Result<()> {
        match self.mode {
            Mode::Compress {
                ref mut input,
                ref mut compressor,
            } => compressor.compress_reader(input, &mut self.output, &self.progress_bar)?,
            Mode::Decompress {
                ref mut decompressor,
                ref from,
                from_frame,
                ref to,
                to_frame,
            } => {
                let offset = match from_frame {
                    Some(frame_index) => decompressor
                        .frame_decompressed_offset(frame_index)
                        .map_err(|e| anyhow!("Failed to get offset of frame {frame_index}: {e}"))?,
                    None => from.as_u64(),
                };

                let limit = match to_frame {
                    Some(frame_index) => {
                        let pos = decompressor
                            .frame_decompressed_offset(frame_index)
                            .map_err(|e| {
                                anyhow!("Failed to get offset of frame {frame_index}: {e}")
                            })?;
                        let size =
                            decompressor
                                .frame_decompressed_size(frame_index)
                                .map_err(|c| {
                                    anyhow!(
                                        "Failed to get size of frame {frame_index}: {}",
                                        zstd_safe::get_error_name(c)
                                    )
                                })?;
                        pos + size as u64
                    }
                    None => to.as_u64(),
                };
                decompressor
                    .decompress(&mut self.output, offset, limit, &self.progress_bar)
                    .context("Failed to decompress seekable object")?;
            }
        };

        if let Some(bar) = self.progress_bar {
            bar.finish_and_clear();
            let input_tuple = self.in_path.and_then(|p| bar.length().map(|len| (p, len)));
            let output_tuple = self
                .output
                .into_out_path()
                .and_then(|p| fs::metadata(&p).map(|m| (p, m.len())).ok());

            if let Some((ref path, len)) = input_tuple {
                eprintln!("Read {} from {}", HumanBytes(len), path.display());
            }
            if let Some((ref path, len)) = output_tuple {
                eprintln!("Wrote {} to {}", HumanBytes(len), path.display());
            }
            if let Some((input_len, output_len)) =
                input_tuple.and_then(|i| output_tuple.map(|o| (i.1, o.1)))
            {
                eprintln!(
                    "{} ratio: {:.2}%",
                    self.mode.as_str(),
                    100. / input_len as f64 * output_len as f64
                );
            }
        }

        Ok(())
    }
}
