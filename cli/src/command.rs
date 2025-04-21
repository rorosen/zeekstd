use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, IsTerminal, Read, Stdin, Write},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};
use zeekstd::{Decoder, EncodeOptions, Encoder, FrameSizePolicy, SeekTable};
use zstd_safe::{CCtx, CParameter};

use crate::args::{CompressArgs, DecompressArgs, ListArgs};

// HumanBytes can mess up intendation if not formatted
#[inline]
fn format_bytes(n: u64) -> String {
    format!("{}", HumanBytes(n))
}

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
    fn is_input_stdin(&self) -> bool {
        self.input_file_str() == Some("-")
    }

    fn input_file(&self) -> &Path {
        match self {
            Command::Compress(CompressArgs { input_file, .. })
            | Command::Decompress(DecompressArgs { input_file, .. })
            | Command::List(ListArgs { input_file, .. }) => input_file,
        }
    }

    fn input_file_str(&self) -> Option<&str> {
        self.input_file().as_os_str().to_str()
    }

    pub fn input_len(&self) -> Option<u64> {
        if self.is_input_stdin() {
            return None;
        }

        fs::metadata(self.input_file()).map(|m| m.len()).ok()
    }

    fn out_path(&self, stdout: bool) -> Option<PathBuf> {
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

    pub fn input(&self) -> Result<Input<'_, '_>> {
        let reader = match self {
            Self::Compress(args) => match self.input_file_str() {
                Some("-") => InputReader::new_stdin(),
                _ => InputReader::new_file(&args.input_file)?,
            },
            Self::Decompress(args) => InputReader::new_decompressor(args)?,
            Self::List(args) => InputReader::new_file(&args.input_file)?,
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

        if let Self::Compress(cargs) = self {
            let mut cctx = CCtx::try_create().context("Failed to create compression context")?;
            cctx.set_parameter(CParameter::CompressionLevel(cargs.compression_level))
                .map_err(|c| {
                    anyhow!(
                        "Failed to set compression level: {}",
                        zstd_safe::get_error_name(c)
                    )
                })?;
            let encoder = EncodeOptions::new()
                .cctx(cctx)
                .with_checksum(!cargs.no_checksum)
                .frame_size_policy(FrameSizePolicy::Decompressed(cargs.max_frame_size.as_u32()))
                .into_encoder(writer)?;

            Ok(Output::Compressor(Box::new(encoder)))
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
            Self::Compress(_) if !stdout => {
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
            Self::Decompress(_) if !stdout => {
                eprintln!("{input_path} : {}", HumanBytes(bytes_read))
            }
            Self::List(args) => {
                let mut file = File::open(&args.input_file).context("Failed to open input file")?;
                let seek_table =
                    SeekTable::from_seekable(&mut file).context("Failed to read seek table")?;

                let start_frame = args.start_frame(&seek_table);
                let end_frame = args.end_frame(&seek_table);

                if start_frame.is_none() && end_frame.is_none() {
                    self.summarize_seekable(&seek_table);
                } else {
                    list_frames(&seek_table, start_frame, end_frame)?;
                }
            }
            _ => (),
        }

        Ok(())
    }

    fn summarize_seekable(&self, seek_table: &SeekTable) {
        let num_frames = seek_table.num_frames();
        let compressed = seek_table
            .frame_end_comp(num_frames - 1)
            .expect("Frame index is never out of range");
        let decompressed = seek_table
            .frame_end_decomp(num_frames - 1)
            .expect("Frame index is never out of range");
        let max_frame_size = seek_table.max_frame_size_decomp();
        let ratio = decompressed as f64 / compressed as f64;

        eprintln!(
            "{: <15} {: <15} {: <15} {: <15} {: <15} {: <15}",
            "Frames", "Compressed", "Decompressed", "Max Frame Size", "Ratio", "Filename"
        );
        eprintln!(
            "{: <15} {: <15} {: <15} {: <15} {: <15.3} {: <15}",
            num_frames,
            format_bytes(compressed),
            format_bytes(decompressed),
            format_bytes(max_frame_size),
            ratio,
            self.input_file_str().unwrap_or("")
        );
    }
}

enum InputReader<'d, 'p> {
    Stdin { stdin: Stdin, bytes_read: u64 },
    File { file: File, bytes_read: u64 },
    Decompressor(Box<Decoder<'d, 'p, File>>),
}

impl InputReader<'_, '_> {
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
        let seekable = File::open(&args.input_file).context("Failed to open input file")?;
        let mut decoder = Decoder::from_seekable(seekable).context("Failed to create decoder")?;
        let lower_frame = match args.from_frame {
            Some(idx) => idx,
            None => decoder.frame_index_decomp(args.from.as_u64()),
        };
        let upper_frame = match args.to_frame {
            Some(idx) => idx,
            None => decoder.frame_index_decomp(args.to.as_u64()),
        };
        decoder
            .set_lower_frame(lower_frame)
            .context("Failed to set lower frame")?;
        decoder.set_upper_frame(upper_frame);

        Ok(Self::Decompressor(Box::new(decoder)))
    }
}

pub struct Input<'d, 'p> {
    bar: Option<ProgressBar>,
    reader: InputReader<'d, 'p>,
}

impl Input<'_, '_> {
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
            InputReader::Decompressor(decompressor) => decompressor.read_uncompressed(),
        }
    }
}

impl<'d, 'p> Read for Input<'d, 'p>
where
    'p: 'd,
{
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

pub enum Output<'c, 'p> {
    Writer {
        writer: Box<dyn Write>,
        bytes_written: u64,
    },
    Compressor(Box<Encoder<'c, 'p, Box<dyn Write>>>),
}

impl Output<'_, '_> {
    pub fn finish(self) -> Result<u64> {
        match self {
            Output::Writer {
                mut writer,
                bytes_written,
            } => {
                writer.flush()?;
                Ok(bytes_written)
            }
            Output::Compressor(compressor) => Ok(compressor.finish()?),
        }
    }
}

impl<'c, 'p: 'c> Write for Output<'c, 'p> {
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

fn list_frames(
    seekable: &SeekTable,
    start_frame: Option<u32>,
    end_frame: Option<u32>,
) -> Result<()> {
    let frame_err_context = |index| format!("Failed to get data of frame {index}");
    // let map_error_code = |index, code| {
    //     anyhow!(
    //         "Failed to get data of frame {index}: {}",
    //         zstd_safe::get_error_name(code)
    //     )
    // };
    // let map_index_err = |index, err| anyhow!("Failed to get data of frame {index}: {err}");

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
                    .frame_size_comp(n)
                    .with_context(|| frame_err_context(n))?
            ),
            format_bytes(
                seekable
                    .frame_size_decomp(n)
                    .with_context(|| frame_err_context(n))?
            ),
            seekable
                .frame_start_comp(n)
                .with_context(|| frame_err_context(n))?,
            seekable
                .frame_start_decomp(n)
                .with_context(|| frame_err_context(n))?,
        );
    }

    Ok(())
}
