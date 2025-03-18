use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, IsTerminal, Read, Stdin, Write},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};
use zstd_safe::seekable::Seekable;

use crate::{
    args::{CompressArgs, DecompressArgs, ListArgs},
    compress::Compressor,
    decompress::Decompressor,
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
            Self::Compress(ref args) => match self.input_file_str() {
                Some("-") => InputReader::new_stdin(),
                _ => InputReader::new_file(&args.input_file)?,
            },
            Self::Decompress(ref args) => InputReader::new_decompressor(args)?,
            Self::List(ref args) => InputReader::new_file(&args.input_file)?,
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
                // Always write to terminal in list mode
                if !force && !matches!(self, Self::List(_)) && stdout.is_terminal() {
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

    pub fn print_summary(&self, bytes_read: u64, bytes_written: u64, stdout: bool) -> Result<()> {
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
            Self::List(ref args) => {
                list_frames(args).context("Failed to list archive content")?;
            }
        }

        Ok(())
    }
}

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
pub fn list_frames(args: &ListArgs) -> Result<()> {
    // Humanbytes mess up intendation if not formatted
    let format_bytes = |n: u64| format!("{}", HumanBytes(n));
    let file = File::open(&args.input_file).context("Failed to open input file")?;
    let seekable = Seekable::try_create().context("Failed to create seekable object")?;
    let seekable = seekable.init_advanced(Box::new(file)).map_err(|c| {
        anyhow!(
            "Failed to initialize seekable object: {}",
            zstd_safe::get_error_name(c)
        )
    })?;

    let start_frame = if args.from_frame.is_some() {
        args.from_frame
    } else {
        args.from
            .as_ref()
            .map(|offset| seekable.offset_to_frame_index(offset.as_u64()))
    };

    let end_frame = if args.to_frame.is_some() {
        args.to_frame
    } else if let Some(offset) = &args.to {
        Some(seekable.offset_to_frame_index(offset.as_u64()))
    } else {
        args.num_frames.map(|num| start_frame.unwrap_or(0) + num)
    };

    if start_frame.is_none() && end_frame.is_none() {
        let frames = seekable.num_frames();
        let compressed = (0..frames).fold(0u64, |acc, n| {
            acc + seekable
                .frame_compressed_size(n)
                .expect("Frame index is never out of range") as u64
        });
        let decompressed_iter = (0..frames).map(|n| {
            seekable
                .frame_decompressed_size(n)
                .expect("Frame index is never out of range") as u64
        });
        let max_frame_size = decompressed_iter.clone().max();
        let decompressed = decompressed_iter.sum::<u64>();
        let ratio = decompressed as f64 / compressed as f64;

        eprintln!(
            "{: <15} {: <15} {: <15} {: <15} {: <15} {: <15}",
            "Frames", "Compressed", "Decompressed", "Max Frame Size", "Ratio", "Filename"
        );
        eprintln!(
            "{: <15} {: <15} {: <15} {: <15} {: <15.3} {: <15}",
            frames,
            format_bytes(compressed),
            format_bytes(decompressed),
            format_bytes(max_frame_size.unwrap_or(0)),
            ratio,
            args.input_file.as_os_str().to_str().unwrap_or("")
        );
    } else {
        let map_error_code = |index, code| {
            anyhow!(
                "Failed to get data of frame {index}: {}",
                zstd_safe::get_error_name(code)
            )
        };
        let map_index_err = |index, err| anyhow!("Failed to get data of frame {index}: {err}");
        let start = start_frame.unwrap_or(0);
        let end = end_frame.unwrap_or_else(|| seekable.num_frames());

        if start > end {
            bail!("Start frame ({start}) cannot be greater than end frame ({end})");
        }

        eprintln!(
            "{: <15} {: <15} {: <15} {: <20} {: <20}",
            "Frame Index", "Compressed", "Decompressed", "Compressed Offset", "Decompressed Offset"
        );
        for n in start..end {
            eprintln!(
                "{: <15} {: <15} {: <15} {: <20} {: <20}",
                n,
                format_bytes(
                    seekable
                        .frame_compressed_size(n)
                        .map_err(|c| map_error_code(n, c))? as u64
                ),
                format_bytes(
                    seekable
                        .frame_decompressed_size(n)
                        .map_err(|c| map_error_code(n, c))? as u64
                ),
                seekable
                    .frame_compressed_offset(n)
                    .map_err(|err| map_index_err(n, err))?,
                seekable
                    .frame_decompressed_offset(n)
                    .map_err(|err| map_index_err(n, err))?,
            );
        }
    }

    Ok(())
}
