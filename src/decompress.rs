use std::{
    io::{Read, Seek, Write},
    ops::{Deref, DerefMut},
};

use anyhow::{anyhow, bail, Context, Result};
use indicatif::ProgressBar;
use zstd_safe::seekable::{AdvancedSeekable, Seekable};

pub struct Decompressor<'a, F> {
    seekable: AdvancedSeekable<'a, F>,
}

impl<'a, F> Deref for Decompressor<'a, F> {
    type Target = AdvancedSeekable<'a, F>;

    fn deref(&self) -> &Self::Target {
        &self.seekable
    }
}

impl<F> DerefMut for Decompressor<'_, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.seekable
    }
}

impl<F> Decompressor<'_, F> {
    pub fn new(src: Box<F>) -> Result<Self>
    where
        F: Read + Seek,
    {
        let seekable =
            Seekable::try_create().context("Failed to create seekable decompression object")?;
        let seekable = seekable.init_advanced(src).map_err(|c| {
            anyhow!(
                "Failed to initialize seekable decompression object: {}",
                zstd_safe::get_error_name(c)
            )
        })?;

        Ok(Self { seekable })
    }

    pub fn decompress<W: Write>(
        &mut self,
        writer: &mut W,
        offset: u64,
        limit: u64,
        bar: &Option<ProgressBar>,
    ) -> Result<()> {
        if offset > limit {
            bail!("End position ({limit}) cannot be greater than start position ({offset})");
        }

        let mut out_buf = Vec::with_capacity(8192);
        let mut current_offset = offset;

        loop {
            if (current_offset + 8192) > limit {
                let rest = (limit - current_offset) as usize;
                out_buf.truncate(rest);
                out_buf.shrink_to(rest);
            }
            let n = self
                .seekable
                .decompress(&mut out_buf, current_offset)
                .map_err(|c| anyhow!(zstd_safe::get_error_name(c)))?;
            if n == 0 {
                break;
            }
            writer
                .write(&out_buf[..n])
                .context("Failed to write decompressed data")?;
            current_offset += n as u64;
            if current_offset >= limit {
                break;
            }
            if let Some(b) = bar {
                b.inc(n as u64);
            }
        }

        writer.flush().context("Failed to flush output")?;
        Ok(())
    }
}
