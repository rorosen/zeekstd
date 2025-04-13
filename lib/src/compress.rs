use xxhash_rust::xxh64::Xxh64;
use zstd_safe::{CCtx, InBuffer, OutBuffer, ResetDirective, WriteBuf, zstd_sys::ZSTD_EndDirective};

use crate::{
    SEEKABLE_MAX_FRAME_SIZE,
    error::{Error, Result},
    frame_log::FrameLog,
};

/// A policy that controls when new frames are started automatically.
pub enum FrameSizePolicy {
    /// Starts a new frame when the compressed size of the current frame exceeds the specified
    /// size.
    ///
    /// The compressed frames can be slightly larger than `size`, depending on the write buffer
    /// size. A new frame will always be started if the decompressed frame size reaches
    /// [`SEEKABLE_MAX_FRAME_SIZE`], independent of the configured compressed size.
    Compressed(u32),
    /// Starts a new frame when the decompressed data of the current frame reaches the specified
    /// size.
    Decompressed(u32),
}

impl Default for FrameSizePolicy {
    /// The default policy starts a new frame when the decompressed data of the current frame
    /// reaches 2MiB.
    fn default() -> Self {
        Self::Decompressed(0x200_000)
    }
}

impl FrameSizePolicy {
    fn size(&self) -> u32 {
        match self {
            FrameSizePolicy::Compressed(size) | FrameSizePolicy::Decompressed(size) => *size,
        }
    }
}

/// Options that configure how data is compressed.
///
/// # Examples
///
/// Create a compressor that starts new frames automatically at the given frame size and doesn't
/// create frame checksums.
///
/// ```
/// use zeekstd::{CompressOptions, FrameSizePolicy};
///
/// let compressor = CompressOptions::new()
///     .frame_size_policy(FrameSizePolicy::Decompressed(8192))
///     .with_checksum(false)
///     .into_compressor()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct CompressOptions<'c, 'p> {
    cctx: Option<CCtx<'c>>,
    frame_policy: FrameSizePolicy,
    with_checksum: bool,
    prefix: Option<&'p [u8]>,
}

impl Default for CompressOptions<'_, '_> {
    fn default() -> Self {
        Self {
            cctx: None,
            frame_policy: FrameSizePolicy::default(),
            with_checksum: true,
            prefix: None,
        }
    }
}

impl<'c, 'p> CompressOptions<'c, 'p>
where
    'p: 'c,
{
    /// Creates a set of options with default initial values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a [`CCtx`].
    pub fn cctx(mut self, cctx: CCtx<'c>) -> Self {
        self.cctx = Some(cctx);
        self
    }

    /// Sets a [`FrameSizePolicy`].
    pub fn frame_size_policy(mut self, policy: FrameSizePolicy) -> Self {
        self.frame_policy = policy;
        self
    }

    /// Whether or not the seek table should include checksums of the uncompressed data.
    ///
    /// The least significant 32 bits of the XXH64 hash of the uncompressed frame data are used as
    /// checksum. Each frame has an individual checksum.
    pub fn with_checksum(mut self, with_checksum: bool) -> Self {
        self.with_checksum = with_checksum;
        self
    }

    /// References a prefix that gets re-applied to every frame.
    ///
    /// Decompression will need same prefix to properly regenerate data. Referencing a prefix
    /// involves building tables, which are dependent on compression parameters. It's a CPU
    /// consuming operation, with non-negligible impact on latency, this shouldn't be used for
    /// small frame sizes. Adding a prefix invalidates any previous prefix or dictionary of the
    /// used [`CCtx`].
    pub fn prefix(mut self, prefix: &'p [u8]) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Creates a [`Compressor`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn into_compressor(self) -> Result<Compressor<'c, 'p>> {
        // SEEKABLE_MAX_FRAME_SIZE always fits in u32
        if self.frame_policy.size() > SEEKABLE_MAX_FRAME_SIZE as u32 {
            return Err(Error::frame_size_too_large());
        }

        let mut cctx = if let Some(cctx) = self.cctx {
            cctx
        } else {
            CCtx::try_create().ok_or(Error::zstd_create("compression context"))?
        };

        if let Some(prefix) = self.prefix {
            cctx.ref_prefix(prefix)?;
        }

        Ok(Compressor {
            cctx,
            frame_policy: self.frame_policy,
            frame_c_size: 0,
            frame_d_size: 0,
            prefix: self.prefix,
            frame_log: FrameLog::new(self.with_checksum),
            xxh64: self.with_checksum.then(|| Xxh64::new(0)),
        })
    }

    /// Creates an [`Encoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn into_encoder<W>(self, writer: W) -> Result<Encoder<'c, 'p, W>> {
        let comp = self.into_compressor()?;

        Ok(Encoder {
            comp,
            out_buf: vec![0; CCtx::out_size()],
            out_buf_pos: 0,
            writer,
        })
    }
}

/// A seekable compressor.
///
/// Performs low level in-memory seekable compression for streams of data.
pub struct Compressor<'c, 'p> {
    cctx: CCtx<'c>,
    frame_policy: FrameSizePolicy,
    frame_c_size: u32,
    frame_d_size: u32,
    prefix: Option<&'p [u8]>,
    frame_log: FrameLog,
    xxh64: Option<Xxh64>,
}

impl Compressor<'_, '_> {
    /// Creates a new `Compressor` with default parameters.
    pub fn new() -> Result<Self> {
        CompressOptions::new().into_compressor()
    }

    fn remaining_frame_space(&self) -> usize {
        let n = match self.frame_policy {
            // SEEKABLE_MAX_FRAME_SIZE always fits in u32
            FrameSizePolicy::Compressed(_) => SEEKABLE_MAX_FRAME_SIZE as u32 - self.frame_d_size,
            FrameSizePolicy::Decompressed(limit) => limit - self.frame_d_size,
        };

        n.try_into().expect("remaining frame space fits in usize")
    }

    fn is_frame_complete(&self) -> bool {
        match self.frame_policy {
            FrameSizePolicy::Compressed(size) => {
                // SEEKABLE_MAX_FRAME_SIZE always fits in u32
                size <= self.frame_c_size || self.frame_d_size >= SEEKABLE_MAX_FRAME_SIZE as u32
            }
            FrameSizePolicy::Decompressed(limit) => limit <= self.frame_d_size,
        }
    }
}

impl<'c, 'p> Compressor<'c, 'p>
where
    'p: 'c,
{
    /// Performs a streaming compression step from `input` to `output`.
    ///
    /// Call this repetitively to consume the input stream. Will return two numbers `(i, o)` where
    /// `i` is the input progress, i.e. the number of bytes that were consumed from `input`, and
    /// `o` is the output progress, i.e. the number of bytes written to `output`. The caller
    /// must check if `input` has been entirely consumed. If not, the caller must make some room
    /// to receive more compressed data, and then present again remaining input data.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize)> {
        let limit = input.len().min(self.remaining_frame_space());
        let mut in_buf = InBuffer::around(&input[..limit]);
        let mut out_buf = OutBuffer::around(output);

        while in_buf.pos() < limit && out_buf.pos() < out_buf.capacity() {
            self.cctx.compress_stream2(
                &mut out_buf,
                &mut in_buf,
                ZSTD_EndDirective::ZSTD_e_continue,
            )?;
        }

        // Casting should always be fine
        self.frame_c_size += out_buf.pos() as u32;
        self.frame_d_size += in_buf.pos() as u32;
        if let Some(xxh) = &mut self.xxh64 {
            xxh.update(&input[..in_buf.pos()]);
        }

        let mut out_progress = out_buf.pos();
        if self.is_frame_complete() {
            out_progress += self.end_frame(&mut output[out_progress..])?;
        }

        Ok((in_buf.pos(), out_progress))
    }

    /// End the current frame and start a new one.
    ///
    /// Call this repetitively to write bytes into `output`. Returns the number of bytes written.
    /// Should be called until `Ok(0)` is returned.
    pub fn end_frame(&mut self, output: &mut [u8]) -> Result<usize> {
        let mut empty_buf = InBuffer::around(&[]);
        let mut out_buf = OutBuffer::around(output);

        loop {
            let prev_out_pos = out_buf.pos();
            let n = self.cctx.compress_stream2(
                &mut out_buf,
                &mut empty_buf,
                ZSTD_EndDirective::ZSTD_e_end,
            )?;

            // Casting should always be fine
            self.frame_c_size += (out_buf.pos() - prev_out_pos) as u32;
            if out_buf.pos() == out_buf.capacity() {
                return Ok(out_buf.pos());
            }

            if n == 0 {
                break;
            }
        }

        let checksum = self
            .xxh64
            .as_ref()
            // Only the least significant 32 bits of the hash are needed, so casting to u32 is ok.
            .map(|x| x.digest() as u32);
        self.frame_log
            .log_frame(self.frame_c_size, self.frame_d_size, checksum)?;
        self.reset_frame()?;

        Ok(out_buf.pos())
    }

    /// Ends the current frame and writes the seek table.
    ///
    /// Call this repetitively to write the seek table into `output`. Returns the number of bytes
    /// written. Should be called until `Ok(0)` is returned.
    pub fn finish(&mut self, output: &mut [u8]) -> Result<usize> {
        let mut written = if self.frame_log.is_writing() {
            0
        } else {
            // Drop the prefix so it doesn't get set again.
            let _ = self.prefix.take();
            self.end_frame(output)?
        };

        while written < output.capacity() {
            let n = self
                .frame_log
                .write_seek_table_into(&mut output[written..])?;

            if n == 0 {
                break;
            }
            written += n;
        }

        Ok(written)
    }

    /// Resets the current frame.
    ///
    /// This will discard any compression progress tracked for the current frame and resets
    /// the compression context.
    pub fn reset_frame(&mut self) -> Result<()> {
        self.frame_c_size = 0;
        self.frame_d_size = 0;
        self.cctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");

        if let Some(xxh) = &mut self.xxh64 {
            xxh.reset(0);
        }

        if let Some(prefix) = self.prefix {
            self.cctx.ref_prefix(prefix)?;
        }

        Ok(())
    }

    /// Transforms this `Compressor` into an encoder.
    ///
    /// Resets any frame progress. The encoder will write all output data to `writer`.
    pub fn into_encoder<W>(mut self, writer: W) -> Result<Encoder<'c, 'p, W>> {
        self.reset_frame()?;

        Ok(Encoder {
            comp: self,
            out_buf: vec![0; CCtx::out_size()],
            out_buf_pos: 0,
            writer,
        })
    }
}

/// Compresses input data into seekable archives.
///
/// The compressed data gets written to an internal writer.
pub struct Encoder<'c, 'p, W> {
    comp: Compressor<'c, 'p>,
    out_buf: Vec<u8>,
    out_buf_pos: usize,
    writer: W,
}

impl<W> Encoder<'_, '_, W> {
    /// Creates a new `Encoder` with default parameters.
    ///
    /// Compressed data gets written to `writer`.
    pub fn new(writer: W) -> Result<Self> {
        CompressOptions::default().into_encoder(writer)
    }
}

impl<'c, 'p, W: std::io::Write> Encoder<'c, 'p, W>
where
    'p: 'c,
{
    /// Compresses data from `buf` and writes it to the internal writer.
    ///
    /// Call this repetitively to consume data. Returns the number of bytes consumed from `buf`.
    pub fn encode(&mut self, buf: &[u8]) -> Result<usize> {
        let mut written = 0;

        while written < buf.len() {
            let (inp_prog, out_prog) = self
                .comp
                .compress(&buf[written..], &mut self.out_buf[self.out_buf_pos..])?;

            if inp_prog == 0 && out_prog == 0 {
                break;
            }

            self.out_buf_pos += out_prog;
            if self.out_buf_pos == self.out_buf.len() {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.out_buf_pos = 0;
            }

            written += inp_prog;
        }

        Ok(written)
    }

    /// Ends the current frame.
    ///
    /// Call this repetitively to write data to the internal writer. Returns the number of bytes
    /// written. Should be called until `Ok(0)` is returned.
    pub fn end_frame(&mut self) -> Result<usize> {
        let mut written = 0;

        loop {
            let n = self.comp.end_frame(&mut self.out_buf[self.out_buf_pos..])?;
            if n == 0 {
                return Ok(written);
            }

            self.out_buf_pos += n;
            if self.out_buf_pos == self.out_buf.len() {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.out_buf_pos = 0;
            }
            written += n;
        }
    }

    /// Ends the current frame and writes the seek table.
    ///
    /// Call this repetitively to write the seek table to the internal writer. Returns the number
    /// of bytes written. Should be called until `Ok(0)` is returned.
    pub fn finish(&mut self) -> Result<usize> {
        let mut written = 0;

        loop {
            let n = self.comp.finish(&mut self.out_buf[self.out_buf_pos..])?;
            if n == 0 {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.writer.flush()?;
                return Ok(written);
            }

            self.out_buf_pos += n;
            if self.out_buf_pos == self.out_buf.len() {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.out_buf_pos = 0;
            }
            written += n;
        }
    }
}

impl<'c, 'p, W: std::io::Write> std::io::Write for Encoder<'c, 'p, W>
where
    'p: 'c,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encode(buf).map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
