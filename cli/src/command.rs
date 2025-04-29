use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::FileTypeExt,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};
use zeekstd::SeekTable;

use crate::{
    args::{CliFlags, CompressArgs, DecompressArgs, ListArgs},
    compress::Compressor,
    decompress::Decompressor,
};

// HumanBytes can mess up intendation if not formatted
#[inline]
fn human_bytes(n: u64) -> String {
    format!("{}", HumanBytes(n))
}

#[inline]
fn raw_bytes(n: u64) -> String {
    format!("{}", n)
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
    fn in_path(&self) -> Option<String> {
        let input_file = match self {
            Command::Compress(CompressArgs { input_file, .. })
            | Command::Decompress(DecompressArgs { input_file, .. })
            | Command::List(ListArgs { input_file, .. }) => input_file.as_str(),
        };

        match input_file {
            "-" => None,
            _ => Some(input_file.into()),
        }
    }

    fn out_path(&self, is_stdout: bool) -> Option<PathBuf> {
        let in_path = self.in_path().map(PathBuf::from);
        let out_path = in_path.as_ref().map(|p| {
            // TODO: Use `add_extension` when stable: https://github.com/rust-lang/rust/issues/127292
            let extension = p.extension().map_or_else(
                || OsString::from("zst"),
                |e| {
                    let mut ext = OsString::from(e);
                    ext.push(".zst");
                    ext
                },
            );

            p.with_extension(extension)
        });

        if is_stdout {
            return None;
        }

        match &self {
            Command::Compress(CompressArgs { output_file, .. }) => output_file.clone().or(out_path),
            Command::Decompress(DecompressArgs { output_file, .. }) => output_file
                .clone()
                // TODO: respect extension (.zst)
                .or_else(|| in_path.map(|p| p.with_extension(""))),
            Command::List(_) => None,
        }
    }

    pub fn run(self, flags: CliFlags) -> Result<()> {
        let in_path = self.in_path();
        let out_path = self.out_path(flags.stdout);

        let writer: Box<dyn Write> = match &out_path {
            Some(path) => {
                let meta = fs::metadata(path).ok();
                if !flags.force
                    && path.exists()
                    && !meta.is_some_and(|m| m.file_type().is_char_device())
                {
                    if flags.quiet || self.in_path().is_none() {
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

                Box::new(File::create(path).context("Failed to open output file")?)
            }
            None => {
                let stdout = io::stdout();
                // Always write to terminal in list mode
                if !flags.force && !matches!(self, Self::List(_)) && stdout.is_terminal() {
                    bail!("stdout is a terminal, aborting");
                }

                Box::new(stdout)
            }
        };

        let byte_fmt = if flags.raw_bytes {
            raw_bytes
        } else {
            human_bytes
        };
        let exec = match self {
            Command::Compress(args) => {
                let reader: Box<dyn Read> = match &in_path {
                    Some(p) => {
                        let file = File::open(p).context("Failed to open input file")?;
                        Box::new(file)
                    }
                    None => Box::new(io::stdin()),
                };
                let mode = ExecMode::Compress {
                    reader,
                    compressor: Compressor::new(&args, writer)?,
                    prefix: args.patch_from,
                    out_path: out_path
                        .and_then(|p| p.to_str().map(|s| s.into()))
                        .unwrap_or("STDOUT".into()),
                    bar: flags
                        .is_with_progress()
                        .then(|| with_bar(in_path.as_deref())),
                };

                Executor {
                    mode,
                    in_path: in_path.unwrap_or("STDIN".into()),
                    byte_fmt,
                }
            }
            Command::Decompress(args) => {
                let mode = ExecMode::Decompress {
                    decompressor: Decompressor::new(&args)?,
                    writer,
                    prefix: args.patch_apply,
                    bar: flags
                        .is_with_progress()
                        .then(|| with_bar(in_path.as_deref())),
                };

                Executor {
                    mode,
                    in_path: args.input_file,
                    byte_fmt,
                }
            }
            Command::List(args) => {
                let mut file = File::open(&args.input_file).context("Failed to open input file")?;
                let seek_table = SeekTable::from_seekable(&mut file)
                    .or_else(|_| SeekTable::from_reader(&file))
                    .context("Failed to read seek table")?;
                let start_frame = args.start_frame(&seek_table);
                let end_frame = args.end_frame(&seek_table);
                let mode = ExecMode::List {
                    seek_table,
                    start_frame,
                    end_frame,
                    detail: args.detail,
                };

                Executor {
                    mode,
                    in_path: args.input_file,
                    byte_fmt,
                }
            }
        };

        exec.run()
    }
}

enum ExecMode<'a> {
    Compress {
        reader: Box<dyn Read>,
        compressor: Compressor<'a, Box<dyn Write>>,
        prefix: Option<PathBuf>,
        out_path: String,
        bar: Option<ProgressBar>,
    },
    Decompress {
        decompressor: Decompressor<'a>,
        writer: Box<dyn Write>,
        prefix: Option<PathBuf>,
        bar: Option<ProgressBar>,
    },
    List {
        seek_table: SeekTable,
        start_frame: Option<u32>,
        end_frame: Option<u32>,
        detail: bool,
    },
}

struct Executor<'a> {
    mode: ExecMode<'a>,
    in_path: String,
    byte_fmt: fn(u64) -> String,
}

impl Executor<'_> {
    fn run(self) -> Result<()> {
        match self.mode {
            ExecMode::Compress {
                mut reader,
                compressor,
                prefix,
                out_path,
                bar,
            } => {
                let pref = prefix
                    .map(|p| fs::read(&p))
                    .transpose()
                    .context("Failed to read prefix to create patch")?;
                let (read, written) =
                    compressor.compress_reader(&mut reader, pref.as_deref(), bar.as_ref())?;

                eprintln!(
                    "{in_path} : {ratio:.2}% ( {bytes_read} => {bytes_written}, {out_path})",
                    in_path = self.in_path,
                    ratio = 100. / read as f64 * written as f64,
                    bytes_read = (self.byte_fmt)(read),
                    bytes_written = (self.byte_fmt)(written),
                    out_path = out_path,
                );
            }
            ExecMode::Decompress {
                decompressor,
                mut writer,
                prefix,
                bar,
            } => {
                let pref = prefix
                    .map(|p| fs::read(&p))
                    .transpose()
                    .context("Failed to read prefix to create patch")?;
                let written =
                    decompressor.decompress_into(&mut writer, pref.as_deref(), bar.as_ref())?;

                eprintln!(
                    "{in_path} : {bytes_written}",
                    in_path = self.in_path,
                    bytes_written = (self.byte_fmt)(written)
                );
            }
            ExecMode::List {
                seek_table,
                start_frame,
                end_frame,
                detail,
            } => {
                if start_frame.is_none() && end_frame.is_none() && !detail {
                    list_summarize(&seek_table, &self.in_path, self.byte_fmt);
                } else {
                    list_frames(&seek_table, start_frame, end_frame, self.byte_fmt)?;
                }
            }
        };

        Ok(())
    }
}

fn list_summarize(st: &SeekTable, in_path: &str, byte_fmt: fn(u64) -> String) {
    let num_frames = st.num_frames();
    let compressed = st
        .frame_end_comp(num_frames - 1)
        .expect("Frame index is never out of range");
    let uncompressed = st
        .frame_end_decomp(num_frames - 1)
        .expect("Frame index is never out of range");
    let ratio = uncompressed as f64 / compressed as f64;
    let compressed = (byte_fmt)(compressed);
    let uncompressed = (byte_fmt)(uncompressed);
    let max_frame_size = (byte_fmt)(st.max_frame_size_decomp());

    println!(
        "{: <15} {: <15} {: <15} {: <15} {: <10} {: <15}",
        "Frames", "Compressed", "Uncompressed", "Max Frame Size", "Ratio", "Filename"
    );
    println!(
        "{num_frames: <15} {compressed: <15} {uncompressed: <15} {max_frame_size: <15} {ratio: <10.3} {in_path: <15}",
    );
}

fn list_frames(
    st: &SeekTable,
    start_frame: Option<u32>,
    end_frame: Option<u32>,
    byte_fmt: fn(u64) -> String,
) -> Result<()> {
    use std::fmt::Write as _;

    let frame_err = |index| format!("Failed to get data of frame {index}");
    let start = start_frame.unwrap_or(0);
    let end = end_frame.unwrap_or_else(|| st.num_frames());
    if start > end {
        bail!("Start frame ({start}) cannot be greater than end frame ({end})");
    }
    // line length (106) times lines
    let mut buf = String::with_capacity(106 * 100);

    println!(
        "{: <15} {: <15} {: <15} {: <20} {: <20}",
        "Frame Index", "Compressed", "Uncompressed", "Compressed Offset", "Uncompressed Offset"
    );

    let mut cnt = 0;
    for n in start..end {
        let comp = (byte_fmt)(st.frame_size_comp(n).with_context(|| frame_err(n))?);
        let uncomp = (byte_fmt)(st.frame_size_decomp(n).with_context(|| frame_err(n))?);
        let comp_off = (byte_fmt)(st.frame_start_comp(n).with_context(|| frame_err(n))?);
        let uncomp_off = (byte_fmt)(st.frame_start_decomp(n).with_context(|| frame_err(n))?);

        writeln!(
            &mut buf,
            "{n: <15} {comp: <15} {uncomp: <15} {comp_off: <20} {uncomp_off: <20}",
        )?;

        cnt += 1;
        if cnt == 100 {
            cnt = 0;
            print!("{buf}");
            buf.clear();
        }
    }
    print!("{buf}");

    Ok(())
}

fn with_bar(in_path: Option<&str>) -> ProgressBar {
    let len = in_path.and_then(|p| fs::metadata(p).map(|m| m.len()).ok());
    ProgressBar::with_draw_target(len, ProgressDrawTarget::stderr_with_hz(5)).with_style(
        ProgressStyle::with_template("{binary_bytes} of {binary_total_bytes}")
            .expect("Static template always works"),
    )
}

// enum InputReader {
//     Reader {
//         reader: Box<dyn Read>,
//         bytes_read: u64,
//     },
//     // Decompressor(Decompressor<Box<dyn Read>>),
// }
//
// impl InputReader {
//     fn with_reader(reader: Box<dyn Read>) -> Self {
//         Self::Reader {
//             reader,
//             bytes_read: 0,
//         }
//     }
// }
//
// pub struct Input {
//     in_path: Option<PathBuf>,
//     bar: Option<ProgressBar>,
//     reader: InputReader,
// }
//
// impl Input {
//     pub fn input_len(&self) -> Option<u64> {
//         self.in_path
//             .as_ref()
//             .map(|p| fs::metadata(p).map(|m| m.len()).ok())
//             .flatten()
//     }
//
//     pub fn with_progress(&mut self, input_len: Option<u64>) {
//         let bar = ProgressBar::with_draw_target(input_len, ProgressDrawTarget::stderr_with_hz(5))
//             .with_style(
//                 ProgressStyle::with_template("{binary_bytes} of {binary_total_bytes}")
//                     .expect("Static template always works"),
//             );
//
//         self.bar = Some(bar);
//     }
//
//     // pub fn bytes_read(&self) -> u64 {
//     //     match &self.reader {
//     //         InputReader::Stdin { bytes_read, .. } => *bytes_read,
//     //         InputReader::File { bytes_read, .. } => *bytes_read,
//     //         InputReader::Decompressor(decompressor) => decompressor.read_uncompressed(),
//     //     }
//     // }
// }
//
// // impl<'d, 'p> Read for Input<'d, 'p>
// // where
// //     'p: 'd,
// // {
// //     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
// //         let n = match &mut self.reader {
// //             InputReader::Stdin {
// //                 stdin: reader,
// //                 bytes_read,
// //             } => {
// //                 let n = reader.read(buf)?;
// //                 *bytes_read += n as u64;
// //                 n
// //             }
// //             InputReader::File {
// //                 file: reader,
// //                 bytes_read,
// //             } => {
// //                 let n = reader.read(buf)?;
// //                 *bytes_read += n as u64;
// //                 n
// //             }
// //             InputReader::Decompressor(decompressor) => decompressor.read(buf)?,
// //         };
// //
// //         if let Some(bar) = &self.bar {
// //             bar.inc(n as u64);
// //             if n == 0 {
// //                 bar.finish_and_clear();
// //             }
// //         }
// //
// //         Ok(n)
// //     }
// // }
//
// enum OutputWriter<'a> {
//     Writer {
//         writer: Box<dyn Write>,
//         bytes_written: u64,
//     },
//     Compressor(Compressor<'a, Box<dyn Write>>),
// }
//
// impl OutputWriter<'_> {
//     fn with_writer(writer: Box<dyn Write>) -> Self {
//         Self::Writer {
//             writer,
//             bytes_written: 0,
//         }
//     }
//
//     // fn with_file(path: impl AsRef<Path>) -> Result<Self> {
//     //     let file = File::create(path).context("Failed to open output file")?;
//     //     Ok(Self::from_writer(Box::new(file)))
//     // }
// }
//
// pub struct Output<'a> {
//     out_path: Option<PathBuf>,
//     writer: OutputWriter<'a>,
// }
//
// // impl Output {
// //     pub fn consume_input<R>(self, input: R) -> Result<u64> {
// //         match self {
// //             Output::Writer {
// //                 mut writer,
// //                 bytes_written,
// //             } => {
// //                 writer.flush()?;
// //                 Ok(bytes_written)
// //             }
// //             Output::Compressor(compressor) => Ok(compressor.finish()?),
// //         }
// //     }
// // }
//
// //
// // impl<'c, 'p: 'c> Write for Output<'c, 'p> {
// //     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
// //         let n = match self {
// //             Self::Writer {
// //                 writer,
// //                 bytes_written,
// //             } => {
// //                 let n = writer.write(buf)?;
// //                 *bytes_written += n as u64;
// //                 n
// //             }
// //             Self::Compressor(compressor) => compressor.write(buf)?,
// //         };
// //         Ok(n)
// //     }
// //
// //     fn flush(&mut self) -> io::Result<()> {
// //         match self {
// //             Self::Writer { writer, .. } => writer.flush(),
// //             Self::Compressor(compressor) => compressor.flush(),
// //         }
// //     }
// // }
//
// fn list_frames_old(
//     seekable: &SeekTable,
//     start_frame: Option<u32>,
//     end_frame: Option<u32>,
//     human: bool,
// ) -> Result<()> {
//     use std::fmt::Write as _;
//
//     let frame_err_context = |index| format!("Failed to get data of frame {index}");
//     let start = start_frame.unwrap_or(0);
//     let end = end_frame.unwrap_or_else(|| seekable.num_frames());
//     if start > end {
//         bail!("Start frame ({start}) cannot be greater than end frame ({end})");
//     }
//     // line length (106) times lines
//     let mut buf = String::with_capacity(106 * 100);
//
//     println!(
//         "{: <15} {: <15} {: <15} {: <20} {: <20}",
//         "Frame Index", "Compressed", "Uncompressed", "Compressed Offset", "Uncompressed Offset"
//     );
//
//     let mut cnt = 0;
//     for n in start..end {
//         cnt += 1;
//         writeln!(
//             &mut buf,
//             "{: <15} {: <15} {: <15} {: <20} {: <20}",
//             n,
//             format_bytes(
//                 seekable
//                     .frame_size_comp(n)
//                     .with_context(|| frame_err_context(n))?,
//                 human
//             ),
//             format_bytes(
//                 seekable
//                     .frame_size_decomp(n)
//                     .with_context(|| frame_err_context(n))?,
//                 human
//             ),
//             format_bytes(
//                 seekable
//                     .frame_start_comp(n)
//                     .with_context(|| frame_err_context(n))?,
//                 human
//             ),
//             format_bytes(
//                 seekable
//                     .frame_start_decomp(n)
//                     .with_context(|| frame_err_context(n))?,
//                 human
//             ),
//         )?;
//
//         if cnt == 100 {
//             cnt = 0;
//             print!("{buf}");
//             buf.clear();
//         }
//     }
//     print!("{buf}");
//
//     Ok(())
// }
