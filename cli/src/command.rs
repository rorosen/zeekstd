use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, IsTerminal, Read, Write},
    ops::Deref,
    os::unix::fs::FileTypeExt,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use indicatif::{HumanBytes, ProgressBar};
use memmap2::Mmap;
use zeekstd::SeekTable;

use crate::{
    args::{CliFlags, CompressArgs, DecompressArgs, ListArgs},
    compress::Compressor,
    decompress::Decompressor,
};

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
        // Always write to terminal in list mode
        let force_write_stdout = !flags.force && !matches!(self, Self::List(_));

        // This is a closure so the writer can be created after the input has been validated
        let new_writer = || -> Result<Box<dyn Write>> {
            match &out_path {
                Some(path) => {
                    let meta = fs::metadata(path).ok();
                    if !flags.force
                        && path.exists()
                        && !meta.is_some_and(|m| m.file_type().is_char_device())
                    {
                        if flags.quiet || in_path.is_none() {
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

                    File::create(path)
                        .context("Failed to open output file")
                        .map(|f| Box::new(f) as Box<dyn Write>)
                }
                None => {
                    let stdout = io::stdout();
                    if !force_write_stdout && stdout.is_terminal() {
                        bail!("stdout is a terminal, aborting");
                    }

                    Ok(Box::new(stdout))
                }
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
                let prefix_len = args
                    .patch_from
                    .as_ref()
                    .and_then(|p| fs::metadata(p).map(|m| m.len()).ok());
                let compressor = Compressor::new(&args, prefix_len, new_writer()?)?;
                let mode = ExecMode::Compress {
                    reader,
                    compressor,
                    prefix: args.patch_from,
                    mmap_prefix: flags.use_mmap(prefix_len),
                    out_path: out_path
                        .and_then(|p| p.to_str().map(|s| s.into()))
                        .unwrap_or("STDOUT".into()),
                    bar: flags.progress_bar(in_path.as_deref()),
                };

                Executor {
                    mode,
                    in_path: in_path.unwrap_or("STDIN".into()),
                    byte_fmt,
                }
            }
            Command::Decompress(args) => {
                let prefix_len = args
                    .patch_apply
                    .as_ref()
                    .and_then(|p| fs::metadata(p).map(|m| m.len()).ok());
                let decompressor = Decompressor::new(&args, prefix_len)?;
                let writer = new_writer()?;

                let mode = ExecMode::Decompress {
                    decompressor,
                    writer,
                    prefix: args.patch_apply,
                    mmap_prefix: flags.use_mmap(prefix_len),
                    bar: flags.progress_bar(in_path.as_deref()),
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
        mmap_prefix: bool,
        out_path: String,
        bar: Option<ProgressBar>,
    },
    Decompress {
        decompressor: Decompressor<'a>,
        writer: Box<dyn Write>,
        prefix: Option<PathBuf>,
        mmap_prefix: bool,
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
                mmap_prefix,
                out_path,
                bar,
            } => {
                let prefix = Prefix::new(prefix, mmap_prefix)
                    .context("Failed to load prefix (patch) file")?;
                let (read, written) =
                    compressor.compress_reader(&mut reader, prefix.as_deref(), bar.as_ref())?;

                eprintln!(
                    "{in_path} : {ratio:.2}% ( {bytes_read} => {bytes_written}, {out_path})",
                    in_path = self.in_path,
                    ratio = 100. / read as f64 * written as f64,
                    bytes_read = (self.byte_fmt)(read),
                    bytes_written = (self.byte_fmt)(written),
                );
            }
            ExecMode::Decompress {
                decompressor,
                mut writer,
                prefix,
                mmap_prefix,
                bar,
            } => {
                let prefix = Prefix::new(prefix, mmap_prefix)
                    .context("Failed to load prefix (patch) file")?;
                let written =
                    decompressor.decompress_into(&mut writer, prefix.as_deref(), bar.as_ref())?;

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

enum Prefix {
    File(Vec<u8>),
    Mmap(Mmap),
}

impl Prefix {
    fn new(prefix: Option<PathBuf>, use_mmap: bool) -> Result<Option<Self>> {
        if let Some(path) = prefix {
            let mut file = File::open(&path)?;
            if use_mmap {
                let mmap = unsafe { Mmap::map(&file)? };
                Ok(Some(Self::Mmap(mmap)))
            } else {
                let size = file.metadata().map(|m| m.len() as usize).ok();
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(size.unwrap_or(0))?;
                file.read_to_end(&mut bytes)?;
                Ok(Some(Self::File(bytes)))
            }
        } else {
            Ok(None)
        }
    }
}

impl Deref for Prefix {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Prefix::File(items) => items,
            Prefix::Mmap(mmap) => mmap,
        }
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
