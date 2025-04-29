use std::{
    fs,
    io::{Read, Write},
};

use anyhow::{Context, Result, anyhow, bail};
use indicatif::ProgressBar;
use zeekstd::{EncodeOptions, Encoder};
use zstd_safe::{CCtx, CParameter};

use crate::args::CompressArgs;

fn highbit_64(mut v: u64) -> Result<u32> {
    if v == 0 {
        bail!("Cannot create patch from empty file");
    }

    let mut count = 0;
    v >>= 1;
    while v > 0 {
        v >>= 1;
        count += 1;
    }

    Ok(count)
}

pub struct Compressor<'a, W> {
    encoder: Encoder<'a, W>,
}

impl<W> Compressor<'_, W> {
    pub fn new(args: &CompressArgs, writer: W) -> Result<Self> {
        let map_err = |msg, c| anyhow!("{msg}: {}", zstd_safe::get_error_name(c));
        let mut cctx = CCtx::try_create().context("Failed to create compression context")?;

        cctx.set_parameter(CParameter::CompressionLevel(args.compression_level))
            .map_err(|c| map_err("Failed to set compression level", c))?;
        cctx.set_parameter(CParameter::ChecksumFlag(!args.no_checksum))
            .map_err(|c| map_err("Failed to set checksum flag", c))?;

        if let Some(old) = &args.patch_from {
            let len = fs::metadata(old)
                .context("Failed to get metadata of patch file")?
                .len();
            let wlog = highbit_64(len + 1024)?;
            cctx.set_parameter(CParameter::WindowLog(wlog))
                .map_err(|c| map_err("Failed to set window log", c))?;
            cctx.set_parameter(CParameter::EnableLongDistanceMatching(true))
                .map_err(|c| map_err("Failed to enable long distance matching", c))?;
        }

        let encoder = EncodeOptions::with_cctx(cctx)
            .frame_size_policy(zeekstd::FrameSizePolicy::Uncompressed(
                args.max_frame_size.as_u32(),
            ))
            .into_encoder(writer);

        Ok(Self { encoder })
    }
}

impl<'a, W: Write> Compressor<'a, W> {
    pub fn compress_reader<'b: 'a, R: Read>(
        mut self,
        reader: &mut R,
        prefix: Option<&'b [u8]>,
        bar: Option<&ProgressBar>,
    ) -> Result<(u64, u64)> {
        let mut buf = vec![0; CCtx::in_size()];
        let mut bytes_read = 0;

        loop {
            let limit = reader.read(&mut buf).context("Failed to read input")?;
            if limit == 0 {
                break;
            }
            bytes_read += limit as u64;
            if let Some(b) = bar {
                b.inc(limit as u64);
            }

            let mut buf_pos = 0;
            while buf_pos < limit {
                let input = &buf[buf_pos..limit];
                let n = self
                    .encoder
                    .compress_with_prefix(input, prefix)
                    .context("Failed to compress data")?;
                buf_pos += n;
            }
        }

        let bytes_written = self
            .encoder
            .finish()
            .context("Failed to finish compression")?;

        if let Some(b) = bar {
            b.finish_and_clear();
        }
        Ok((bytes_read, bytes_written))
    }
}
