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
    /// size. A new frame will always be started if the uncompressed frame size reaches
    /// [`SEEKABLE_MAX_FRAME_SIZE`], independent of the configured compressed size.
    Compressed(u32),
    /// Starts a new frame when the uncompressed data of the current frame reaches the specified
    /// size.
    Uncompressed(u32),
}

impl Default for FrameSizePolicy {
    /// The default policy starts a new frame when the uncompressed data of the current frame
    /// reaches 2MiB.
    fn default() -> Self {
        Self::Uncompressed(0x200_000)
    }
}

impl FrameSizePolicy {
    fn size(&self) -> u32 {
        match self {
            FrameSizePolicy::Compressed(size) | FrameSizePolicy::Uncompressed(size) => *size,
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
/// use zeekstd::{EncodeOptions, FrameSizePolicy};
///
/// let compressor = EncodeOptions::new()
///     .frame_size_policy(FrameSizePolicy::Uncompressed(8192))
///     .with_checksum(false)
///     .into_raw_encoder()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct EncodeOptions<'c, 'p> {
    cctx: Option<CCtx<'c>>,
    frame_policy: FrameSizePolicy,
    with_checksum: bool,
    prefix: Option<&'p [u8]>,
}

impl Default for EncodeOptions<'_, '_> {
    fn default() -> Self {
        Self {
            cctx: None,
            frame_policy: FrameSizePolicy::default(),
            with_checksum: true,
            prefix: None,
        }
    }
}

impl<'c, 'p> EncodeOptions<'c, 'p>
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

    /// Creates a [`RawEncoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn into_raw_encoder(self) -> Result<RawEncoder<'c, 'p>> {
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

        Ok(RawEncoder {
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
        let comp = self.into_raw_encoder()?;

        Ok(Encoder {
            raw: comp,
            out_buf: vec![0; CCtx::out_size()],
            out_buf_pos: 0,
            writer,
            written_compressed: 0,
        })
    }
}

/// A seekable compressor.
///
/// Performs low level in-memory seekable compression for streams of data.
pub struct RawEncoder<'c, 'p> {
    cctx: CCtx<'c>,
    frame_policy: FrameSizePolicy,
    frame_c_size: u32,
    frame_d_size: u32,
    prefix: Option<&'p [u8]>,
    frame_log: FrameLog,
    xxh64: Option<Xxh64>,
}

impl RawEncoder<'_, '_> {
    /// Creates a new `RawEncoder` with default parameters.
    pub fn new() -> Result<Self> {
        EncodeOptions::new().into_raw_encoder()
    }

    fn remaining_frame_space(&self) -> usize {
        let n = match self.frame_policy {
            // SEEKABLE_MAX_FRAME_SIZE always fits in u32
            FrameSizePolicy::Compressed(_) => SEEKABLE_MAX_FRAME_SIZE as u32 - self.frame_d_size,
            FrameSizePolicy::Uncompressed(limit) => limit - self.frame_d_size,
        };

        n.try_into().expect("Remaining frame space fits in usize")
    }

    fn is_frame_complete(&self) -> bool {
        match self.frame_policy {
            FrameSizePolicy::Compressed(size) => {
                // SEEKABLE_MAX_FRAME_SIZE always fits in u32
                size <= self.frame_c_size || self.frame_d_size >= SEEKABLE_MAX_FRAME_SIZE as u32
            }
            FrameSizePolicy::Uncompressed(limit) => limit <= self.frame_d_size,
        }
    }
}

impl<'c, 'p> RawEncoder<'c, 'p>
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

        // Casting these is always fine
        self.frame_c_size += out_buf.pos() as u32;
        self.frame_d_size += in_buf.pos() as u32;
        if let Some(xxh) = &mut self.xxh64 {
            xxh.update(&input[..in_buf.pos()]);
        }

        let mut out_progress = out_buf.pos();
        if self.is_frame_complete() {
            while out_progress < output.len() {
                let (out_prog, n) = self.end_frame(&mut output[out_progress..])?;
                out_progress += out_prog;
                if n == 0 {
                    break;
                }
            }
        }

        Ok((in_buf.pos(), out_progress))
    }

    /// Ends the current frame.
    ///
    /// Call this repetitively to write the frame epilogue to `output`. Returns two numbers,
    /// `(o, n)` where `o` is the number of bytes written to `output`, and `n` is a minimal
    /// estimation of the bytes left to flush. Should be called until `n` is zero.
    pub fn end_frame(&mut self, output: &mut [u8]) -> Result<(usize, usize)> {
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
                return Ok((out_buf.pos(), n));
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

        // If we get here the frame is complete
        Ok((out_buf.pos(), 0))
    }

    /// Writes the seek table to `output`.
    ///
    /// Call this repetitively to write the seek table to `output`. Returns the number of bytes
    /// written. Should be called until `0` is returned.
    pub fn write_seek_table_into(&mut self, output: &mut [u8]) -> usize {
        let mut written = 0;
        while written < output.capacity() {
            let n = self.frame_log.write_seek_table_into(&mut output[written..]);

            if n == 0 {
                break;
            }
            written += n;
        }

        written
    }

    /// Removes the referenced prefix, if any.
    ///
    /// Removes and returns the referenced prefix. Call this to improve compression speed, if a
    /// previously referenced prefix isn't needed anymore.
    pub fn remove_prefix(&mut self) -> Option<&'p [u8]> {
        self.prefix.take()
    }

    /// Sets a new prefix that gets referenced for every frame.
    ///
    /// Decompression will need same prefix to properly regenerate data. Referencing a prefix
    /// involves building tables, which are dependent on compression parameters. It's a CPU
    /// consuming operation, with non-negligible impact on latency, this shouldn't be used for
    /// small frame sizes. Setting a prefix resets any frame prefix and invalidates any previous
    /// prefix.
    pub fn set_prefix(&mut self, prefix: &'p [u8]) -> Result<()> {
        self.remove_prefix();
        self.reset_frame()?;
        self.prefix = Some(prefix);

        Ok(())
    }

    /// Resets the current frame.
    ///
    /// This will discard any compression progress tracked for the current frame and resets
    /// the compression session.
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

    /// Transforms this `RawEncoder` into an [`Encoder`].
    ///
    /// Resets any frame progress. The encoder will write all output data to `writer`.
    pub fn into_encoder<W>(mut self, writer: W) -> Result<Encoder<'c, 'p, W>> {
        self.reset_frame()?;

        Ok(Encoder {
            raw: self,
            out_buf: vec![0; CCtx::out_size()],
            out_buf_pos: 0,
            writer,
            written_compressed: 0,
        })
    }
}

/// Compresses input data into seekable archives.
///
/// The compressed data gets written to an internal writer.
pub struct Encoder<'c, 'p, W> {
    raw: RawEncoder<'c, 'p>,
    out_buf: Vec<u8>,
    out_buf_pos: usize,
    writer: W,
    written_compressed: u64,
}

impl<W> Encoder<'_, '_, W> {
    /// Creates a new `Encoder` with default parameters.
    ///
    /// Compressed data gets written to `writer`.
    pub fn new(writer: W) -> Result<Self> {
        EncodeOptions::default().into_encoder(writer)
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
        let mut input_progress = 0;

        while input_progress < buf.len() {
            let (inp_prog, out_prog) = self.raw.compress(
                &buf[input_progress..],
                &mut self.out_buf[self.out_buf_pos..],
            )?;

            if inp_prog == 0 && out_prog == 0 {
                break;
            }

            self.out_buf_pos += out_prog;
            self.flush_out_buf()?;
            input_progress += inp_prog;
        }

        Ok(input_progress)
    }

    /// Ends the current frame.
    ///
    /// Call this to write the frame epilogue to the internal writer. Returns the number of bytes
    /// written.
    pub fn end_frame(&mut self) -> Result<usize> {
        let mut progress = 0;

        loop {
            let (prog, n) = self.raw.end_frame(&mut self.out_buf[self.out_buf_pos..])?;
            self.out_buf_pos += prog;
            self.flush_out_buf()?;
            progress += prog;

            if n == 0 {
                return Ok(progress);
            }
        }
    }

    /// Ends the current frame and writes the seek table.
    ///
    /// Call this to write the seek table to the internal writer. Returns the total number of
    /// compressed bytes written by this `Encoder`.
    pub fn finish(mut self) -> Result<u64> {
        let mut progress = 0;
        self.raw.remove_prefix();

        loop {
            let (prog, n) = self.raw.end_frame(&mut self.out_buf[self.out_buf_pos..])?;
            self.out_buf_pos += prog;
            self.flush_out_buf()?;
            progress += prog;

            if n == 0 {
                break;
            }
        }

        loop {
            let n = self
                .raw
                .write_seek_table_into(&mut self.out_buf[self.out_buf_pos..]);
            if n == 0 {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.writer.flush()?;
                return Ok(self.written_compressed + progress as u64);
            }

            self.out_buf_pos += n;
            self.flush_out_buf()?;
            progress += n;
        }
    }

    /// Get the total number of compressed bytes written to the internal writer so far.
    pub fn written_compressed(&self) -> u64 {
        self.written_compressed
    }

    /// Flushes `self.out_buf`, if it is full with new data
    #[inline]
    fn flush_out_buf(&mut self) -> Result<()> {
        if self.out_buf_pos == self.out_buf.len() {
            self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
            self.written_compressed += self.out_buf_pos as u64;
            self.out_buf_pos = 0;
        }

        Ok(())
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
