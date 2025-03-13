use std::io::{self, Read, Seek};

use anyhow::{anyhow, bail, Context, Result};
use zstd_safe::seekable::{AdvancedSeekable, Seekable};

use crate::args::DecompressArgs;

pub struct Decompressor<'a, F> {
    seekable: AdvancedSeekable<'a, F>,
    offset: u64,
    limit: u64,
    bytes_read: u64,
}

impl<F> Decompressor<'_, F> {
    pub fn new(src: F, args: &DecompressArgs) -> Result<Self>
    where
        F: Read + Seek,
    {
        let seekable =
            Seekable::try_create().context("Failed to create seekable decompression object")?;
        let seekable = seekable.init_advanced(Box::new(src)).map_err(|c| {
            anyhow!(
                "Failed to initialize seekable decompression object: {}",
                zstd_safe::get_error_name(c)
            )
        })?;

        let offset = match args.from_frame {
            Some(frame_index) => seekable
                .frame_decompressed_offset(frame_index)
                .map_err(|e| anyhow!("Failed to get offset of frame {frame_index}: {e}"))?,
            None => args.from.as_u64(),
        };

        let limit = match args.to_frame {
            Some(frame_index) => {
                let pos = seekable
                    .frame_decompressed_offset(frame_index)
                    .map_err(|e| anyhow!("Failed to get offset of frame {frame_index}: {e}"))?;
                let size = seekable.frame_decompressed_size(frame_index).map_err(|c| {
                    anyhow!(
                        "Failed to get size of frame {frame_index}: {}",
                        zstd_safe::get_error_name(c)
                    )
                })?;
                pos + size as u64
            }
            None => args.to.as_u64(),
        };

        if offset > limit {
            bail!("End offset ({limit}) cannot be greater than start offset ({offset})");
        }

        Ok(Self {
            seekable,
            offset,
            limit,
            bytes_read: 0,
        })
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<F> Read for Decompressor<'_, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = if (self.offset + buf.len() as u64) > self.limit {
            (self.limit - self.offset) as usize
        } else {
            buf.len()
        };

        let n = self
            .seekable
            .decompress(&mut buf[..len], self.offset)
            .map_err(|c| {
                io::Error::other(format!(
                    "Failed to decompress data: {}",
                    zstd_safe::get_error_name(c)
                ))
            })?;

        self.offset += n as u64;
        self.bytes_read += n as u64;
        Ok(n)
    }
}
