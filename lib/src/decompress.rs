use std::{
    io::{self, BufRead, Read, Seek, SeekFrom},
    ops::Deref,
};

use xxhash_rust::xxh64::Xxh64;
use zstd_safe::{DCtx, InBuffer, OutBuffer, ResetDirective};

use crate::{
    error::{Error, Result},
    seek_table::SeekTable,
};

/// A builder that creates a [`Decompressor`] with custom configuration.
#[derive(Default)]
pub struct DecompressorBuilder<'d, 'p> {
    dctx: Option<DCtx<'d>>,
    prefix: Option<&'p [u8]>,
    start_frame: Option<u32>,
    end_frame: Option<u32>,
}

impl<'d, 'p> DecompressorBuilder<'d, 'p>
where
    'p: 'd,
{
    /// Creates a new [`DecompressorBuilder`] with default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`DCtx`] of this builder.
    pub fn dctx(mut self, dctx: DCtx<'d>) -> Self {
        self.dctx = Some(dctx);
        self
    }

    /// Reference a prefix for every frame.
    ///
    /// This is the reverse operation of setting a prefix during compression and must be the same
    /// prefix as the one used during compression. Referencing a raw content prefix has almost no
    /// cpu nor memory cost.
    pub fn prefix(mut self, prefix: &'p [u8]) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// The index of the frame where decompression should start.
    pub fn start_frame(mut self, index: u32) -> Self {
        self.start_frame = Some(index);
        self
    }

    /// The index of the frame where decompression should end.
    ///
    /// The frame at `index` is included in decompression.
    pub fn end_frame(mut self, index: u32) -> Self {
        self.end_frame = Some(index);
        self
    }

    /// Create a [`Decompressor`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn build<S>(self, mut src: S) -> Result<Decompressor<'d, 'p, S>>
    where
        S: Seek + BufRead,
    {
        let mut dctx = if let Some(dctx) = self.dctx {
            dctx
        } else {
            DCtx::try_create().ok_or(Error::zstd_create("decompression context"))?
        };

        if let Some(prefix) = self.prefix {
            dctx.ref_prefix(prefix)?;
        }

        let capacity = DCtx::in_size();
        let seek_table = SeekTable::from_seekable(&mut src)?;
        let xxh64 = seek_table.with_checksum().then(|| Xxh64::new(0));
        let start_frame = self.start_frame.unwrap_or(0);
        let end_frame = self
            .end_frame
            .unwrap_or_else(|| seek_table.num_frames() - 1);

        Ok(Decompressor {
            dctx,
            src,
            seek_table,
            prefix: self.prefix,
            src_pos: 0,
            xxh64,
            in_buf: vec![0; capacity],
            in_buf_pos: 0,
            in_buf_limit: 0,
            start_frame,
            end_frame,
        })
    }
}

/// A decompression stream.
///
/// Read from the stream to decompress data.
pub struct Decompressor<'d, 'p, S> {
    dctx: DCtx<'d>,
    src: S,
    seek_table: SeekTable,
    prefix: Option<&'p [u8]>,
    src_pos: u64,
    xxh64: Option<Xxh64>,
    in_buf: Vec<u8>,
    in_buf_pos: usize,
    in_buf_limit: usize,
    start_frame: u32,
    end_frame: u32,
}

impl<S> Decompressor<'_, '_, S> {
    /// Set the index of the frame where decompression should start the next read.
    ///
    /// This will abort any ongoing decompression.
    pub fn set_start_frame(&mut self, index: u32) {
        self.start_frame = index;
        self.src_pos = 0;
    }

    /// Set the index of the frame where decompression should end.
    ///
    /// Decompression stops at the end of the specified frame index.
    pub fn set_end_frame(&mut self, index: u32) {
        self.end_frame = index;
    }
}

impl<S: Seek + BufRead> Decompressor<'_, '_, S> {
    pub fn new(src: S) -> Result<Self> {
        DecompressorBuilder::default().build(src)
    }
}

impl<S> Deref for Decompressor<'_, '_, S> {
    type Target = SeekTable;

    fn deref(&self) -> &Self::Target {
        &self.seek_table
    }
}

impl<'d, 'p, S> Read for Decompressor<'d, 'p, S>
where
    S: Seek + Read,
    'p: 'd,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let prefix_error = |c| {
            io::Error::other(format!(
                "failed to set prefix: {}",
                zstd_safe::get_error_name(c)
            ))
        };
        let frame_index_error = |id, err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{id} frame invalid: {err}"),
            )
        };

        let end_pos = self
            .seek_table
            .frame_compressed_end(self.end_frame)
            .map_err(|e| frame_index_error("end", e))?;

        if self.src_pos == 0 {
            let start_pos = self
                .seek_table
                .frame_compressed_start(self.start_frame)
                .map_err(|e| frame_index_error("start", e))?;
            self.src.seek(SeekFrom::Start(start_pos))?;
            self.src_pos = start_pos;

            if let Some(prefix) = self.prefix {
                self.dctx
                    .reset(ResetDirective::SessionOnly)
                    .expect("Resetting session never fails");

                self.dctx.ref_prefix(prefix).map_err(prefix_error)?;
            }

            if let Some(xxh) = &mut self.xxh64 {
                xxh.reset(0);
            }
        }

        let mut out_buffer = OutBuffer::around(&mut buf[..]);
        while self.src_pos < end_pos && out_buffer.pos() < out_buffer.capacity() {
            if self.in_buf_pos == self.in_buf_limit {
                self.in_buf_pos = 0;
                let limit = self
                    .in_buf
                    .capacity()
                    .min(end_pos as usize - self.src_pos as usize);
                let read = self.src.read(&mut self.in_buf[..limit])?;
                self.in_buf_limit = read;
            }

            let mut in_buffer = InBuffer::around(&self.in_buf[..self.in_buf_limit]);
            in_buffer.set_pos(self.in_buf_pos);

            let prev_out_pos = out_buffer.pos();
            let ret = self
                .dctx
                .decompress_stream(&mut out_buffer, &mut in_buffer)
                .map_err(|c| {
                    io::Error::other(format!(
                        "failed to decompress data: {}",
                        zstd_safe::get_error_name(c)
                    ))
                })?;

            if let Some(xxh) = &mut self.xxh64 {
                xxh.update(&out_buffer.as_slice()[prev_out_pos..out_buffer.pos()]);
            }

            if ret == 0 {
                if let Some(prefix) = self.prefix {
                    self.dctx
                        .reset(ResetDirective::SessionOnly)
                        .expect("Resetting session never fails");

                    self.dctx.ref_prefix(prefix).map_err(prefix_error)?;
                }

                if let Some(xxh) = &mut self.xxh64 {
                    let index = self
                        .seek_table
                        .frame_index_at_compressed_offset(self.src_pos);
                    let checksum = self.seek_table.frame_checksum(index).unwrap();

                    if (xxh.digest() & 0xFFFFFFFF) as u32 != checksum {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("checksum mismatch for frame {index}"),
                        ));
                    }

                    xxh.reset(0);
                }
            }

            self.src_pos += (in_buffer.pos() - self.in_buf_pos) as u64;
            self.in_buf_pos = in_buffer.pos();
        }

        Ok(out_buffer.pos())
    }
}
