use zstd_safe::{
    CCtx, CParameter, CompressionLevel, InBuffer, OutBuffer, ResetDirective,
    zstd_sys::ZSTD_EndDirective,
};

use crate::{SEEKABLE_MAX_FRAME_SIZE, SeekTable, error::Result, seek_table::Format};

// Constant value always can be casted
const MAX_FRAME_SIZE: u32 = SEEKABLE_MAX_FRAME_SIZE as u32;

/// A policy that controls when new frames are started automatically.
///
/// The uncompressed frame size will never get greater than [`SEEKABLE_MAX_FRAME_SIZE`],
/// independent of the frame size policy in use, i.e. a new frame will **always** be started if
/// the uncompressed frame size reaches [`SEEKABLE_MAX_FRAME_SIZE`].
#[derive(Debug, Clone)]
pub enum FrameSizePolicy {
    /// Starts a new frame when the compressed size of the current frame exceeds the specified
    /// size.
    ///
    /// This will not accurately limit the compressed frame size, but start a new frame if
    /// the compressed frame size is equal to or exceeds the configured value.
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

/// The progress of a compression step.
#[derive(Debug)]
pub struct CompressionProgress {
    /// The input progress, i.e. the number of bytes that were consumed from the input buffer.
    pub input: usize,
    /// The output progress, i.e. the number of bytes that were written to the output buffer.
    pub output: usize,
}

impl CompressionProgress {
    fn new(input: usize, output: usize) -> Self {
        Self { input, output }
    }
}

/// The progress of writing the frame epilogue.
#[derive(Debug)]
pub struct EpilogueProgress {
    /// The output progress, i.e. the number of bytes that were written to the output buffer.
    pub output: usize,
    /// A minimal estimation of the bytes left to flush. The epilogue is entirely written if this
    /// value is zero.
    pub left: usize,
}

impl EpilogueProgress {
    fn new(output: usize, left: usize) -> Self {
        Self { output, left }
    }
}

/// Options that configure how data is compressed.
///
/// # Examples
///
/// Supports builder like chaining.
///
/// ```
/// use zeekstd::{EncodeOptions, FrameSizePolicy};
///
/// let raw_encoder = EncodeOptions::new()
///     .checksum_flag(false)
///     .compression_level(5)
///     .frame_size_policy(FrameSizePolicy::Uncompressed(8192))
///     .into_raw_encoder()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct EncodeOptions<'a> {
    cctx: CCtx<'a>,
    frame_policy: FrameSizePolicy,
    checksum_flag: bool,
    compression_level: CompressionLevel,
}

impl Default for EncodeOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EncodeOptions<'a> {
    /// Creates a set of options with default initial values.
    ///
    /// # Panics
    ///
    /// If allocation of [`CCtx`] fails.
    pub fn new() -> Self {
        Self::with_cctx(CCtx::create())
    }

    /// Tries to create new options with default initial values.
    ///
    /// Returns `None` if allocation of [`CCtx`] fails.
    pub fn try_new() -> Option<Self> {
        let cctx = CCtx::try_create()?;
        Some(Self::with_cctx(cctx))
    }

    /// Create options with the given compression context.
    pub fn with_cctx(cctx: CCtx<'a>) -> Self {
        Self {
            cctx,
            frame_policy: FrameSizePolicy::default(),
            checksum_flag: false,
            compression_level: CompressionLevel::default(),
        }
    }

    /// Sets a [`CCtx`].
    pub fn cctx(mut self, cctx: CCtx<'a>) -> Self {
        self.cctx = cctx;
        self
    }

    /// Sets a [`FrameSizePolicy`].
    pub fn frame_size_policy(mut self, policy: FrameSizePolicy) -> Self {
        self.frame_policy = policy;
        self
    }

    /// Whether to write 32 bit checksums at the end of frames.
    pub fn checksum_flag(mut self, flag: bool) -> Self {
        self.checksum_flag = flag;
        self
    }

    /// Sets the compression level used by zstd.
    pub fn compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Creates a [`RawEncoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the raw encoder cannot be created.
    pub fn into_raw_encoder(self) -> Result<RawEncoder<'a>> {
        RawEncoder::with_opts(self)
    }

    /// Creates an [`Encoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the encoder cannot be created.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::EncodeOptions;
    ///
    /// let output = File::create("data.zst").unwrap();
    /// let raw = EncodeOptions::new()
    ///     .checksum_flag(true)
    ///     .into_encoder(output)
    ///     .unwrap();
    /// ```
    pub fn into_encoder<W>(self, writer: W) -> Result<Encoder<'a, W>> {
        Encoder::with_opts(writer, self)
    }
}

/// A reusable, seekable encoder.
///
/// Performs low level in-memory seekable compression for streams of data.
///
/// # Example
///
/// ```
/// use zeekstd::RawEncoder;
///
/// let mut encoder = RawEncoder::new()?;
/// let mut buf = vec![0; 1024];
///
/// encoder.compress(b"Hello, World!", &mut buf)?;
/// encoder.end_frame(&mut buf)?;
///
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct RawEncoder<'a> {
    cctx: CCtx<'a>,
    frame_policy: FrameSizePolicy,
    frame_c_size: u32,
    frame_d_size: u32,
    seek_table: SeekTable,
}

impl<'a> RawEncoder<'a> {
    /// Creates a new `RawEncoder` with default parameters.
    ///
    /// This is equivalent to calling `EncodeOptions::new().into_raw_encoder()`.
    ///
    /// # Errors
    ///
    /// Fails if the raw encoder could not be created.
    pub fn new() -> Result<Self> {
        Self::with_opts(EncodeOptions::new())
    }

    /// Creates a new `RawEncoder` with the given [`EncodeOptions`].
    ///
    /// # Errors
    ///
    /// Fails if the raw encoder could not be created.
    pub fn with_opts(mut opts: EncodeOptions<'a>) -> Result<Self> {
        opts.cctx
            .set_parameter(CParameter::CompressionLevel(opts.compression_level))?;
        opts.cctx
            .set_parameter(CParameter::ChecksumFlag(opts.checksum_flag))?;

        Ok(Self {
            cctx: opts.cctx,
            frame_policy: opts.frame_policy,
            frame_c_size: 0,
            frame_d_size: 0,
            seek_table: SeekTable::new(),
        })
    }

    /// Performs a streaming compression step from `input` to `output`.
    ///
    /// Call this repetitively to consume the input stream. The returned [`CompressionProgress`]
    /// indicates how many bytes were consumed from `input` and written to `output`. The caller
    /// must check if `input` has been entirely consumed. If not, the caller must make some room
    /// to receive more compressed data, and then present again remaining input data.
    ///
    /// If a `prefix` is passed, it will be re-applied to every frame, as tables are discarded at
    /// end of frame. Referencing a prefix involves building tables, which is a CPU consuming
    /// operation, with non-negligible impact on latency. This should be avoided for small frame
    /// sizes. If there is a need to use the same prefix multiple times without long distance mode,
    /// consider loading a dictionary into the compression context instead.
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress_with_prefix<'b: 'a>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<CompressionProgress> {
        if self.is_frame_complete() {
            let mut out_progress = 0;
            while out_progress < output.len() {
                let progress = self.end_frame(&mut output[out_progress..])?;
                out_progress += progress.output;
                if progress.left == 0 {
                    break;
                }
            }

            Ok(CompressionProgress::new(0, out_progress))
        } else {
            let limit = input.len().min(self.remaining_frame_size());
            let mut in_buf = InBuffer::around(&input[..limit]);
            let mut out_buf = OutBuffer::around(output);
            // Reference prefix at the beginning of a frame
            // TODO: chain when stable
            if let Some(pref) = prefix {
                if self.frame_d_size == 0 {
                    self.cctx.ref_prefix(pref)?;
                }
            }

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

            Ok(CompressionProgress::new(in_buf.pos(), out_buf.pos()))
        }
    }

    fn remaining_frame_size(&self) -> usize {
        let n = match self.frame_policy {
            FrameSizePolicy::Compressed(_) => MAX_FRAME_SIZE - self.frame_d_size,
            FrameSizePolicy::Uncompressed(limit) => MAX_FRAME_SIZE.min(limit) - self.frame_d_size,
        };

        n.try_into().expect("Remaining frame size fits in usize")
    }

    fn is_frame_complete(&self) -> bool {
        match self.frame_policy {
            FrameSizePolicy::Compressed(size) => {
                size <= self.frame_c_size || MAX_FRAME_SIZE <= self.frame_d_size
            }
            FrameSizePolicy::Uncompressed(limit) => MAX_FRAME_SIZE.min(limit) <= self.frame_d_size,
        }
    }
}

impl RawEncoder<'_> {
    /// Performs a streaming compression step from `input` to `output`.
    ///
    /// Call this repetitively to consume the input stream. The returned [`CompressionProgress`]
    /// indicates how many bytes were consumed from `input` and written to `output`. The caller
    /// must check if `input` has been entirely consumed. If not, the caller must make some room
    /// to receive more compressed data, and then present again remaining input data.
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<CompressionProgress> {
        self.compress_with_prefix(input, output, None)
    }

    /// Ends the current frame and adds it to the seek table.
    ///
    /// Call this repetitively to write the frame epilogue to `output`. The returned
    /// [`EpilogueProgress`] indicates how many bytes were written to `output` and provides a
    /// minimal estimation of how many bytes are left to flush. Should be called until no more
    /// bytes are left to flush.
    ///
    /// # Errors
    ///
    /// Fails if the frame epilogue cannot be created or the frame limit is reached.
    pub fn end_frame(&mut self, output: &mut [u8]) -> Result<EpilogueProgress> {
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

            // Check first if writing the frame epilogue finished before checking whether the out
            // buffer is full. Changing the order leads to frames not beeing logged when the frame
            // epilogue fits exactly in the buffer.
            if n == 0 {
                break;
            }

            if out_buf.pos() == out_buf.capacity() {
                return Ok(EpilogueProgress::new(out_buf.pos(), n));
            }
        }

        self.seek_table
            .log_frame(self.frame_c_size, self.frame_d_size)?;
        self.reset_frame();

        // If we get here the frame is complete
        Ok(EpilogueProgress::new(out_buf.pos(), 0))
    }

    /// Returns a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.seek_table
    }

    /// Consumes this raw encoder and returns the internal [`SeekTable`].
    pub fn into_seek_table(self) -> SeekTable {
        self.seek_table
    }

    /// Resets the current frame.
    ///
    /// This will discard any compression progress for the current frame and resets the
    /// compression session.
    #[allow(clippy::missing_panics_doc)]
    pub fn reset_frame(&mut self) {
        self.frame_c_size = 0;
        self.frame_d_size = 0;
        self.cctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");
    }

    /// Resets the internal [`SeekTable`].
    ///
    /// Note that this does not reset the current frame, in most cases this function should be
    /// called together with `reset_frame()`.
    ///
    /// # Example
    ///
    /// ```
    /// # use zeekstd::RawEncoder;
    /// # let mut encoder = RawEncoder::new().unwrap();
    /// encoder.reset_frame();
    /// encoder.reset_seek_table();
    /// assert_eq!(encoder.seek_table().num_frames(), 0);
    /// ```
    pub fn reset_seek_table(&mut self) {
        self.seek_table = SeekTable::new();
    }
}

/// A single-use seekable encoder.
pub struct Encoder<'a, W> {
    raw: RawEncoder<'a>,
    out_buf: Vec<u8>,
    out_buf_pos: usize,
    writer: W,
    written_compressed: u64,
}

impl<'a, W> Encoder<'a, W> {
    /// Creates a new `Encoder` with default parameters.
    ///
    /// This is equivalent to calling `EncodeOptions::new().into_encoder(writer)`.
    ///
    /// # Errors
    ///
    /// Fails if the encoder could not be created.
    pub fn new(writer: W) -> Result<Self> {
        Self::with_opts(writer, EncodeOptions::new())
    }

    /// Creates a new `Encoder` with the given [`EncodeOptions`].
    ///
    /// # Errors
    ///
    /// Fails if the encoder could not be created.
    pub fn with_opts(writer: W, opts: EncodeOptions<'a>) -> Result<Self> {
        Ok(Self {
            raw: opts.into_raw_encoder()?,
            out_buf: vec![0; CCtx::out_size()],
            out_buf_pos: 0,
            writer,
            written_compressed: 0,
        })
    }

    /// Returns a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.raw.seek_table
    }
}

impl<'a, W: std::io::Write> Encoder<'a, W> {
    /// Consumes and compresses input data from `buf`.
    ///
    /// Call this repetitively to consume input data. Compressed data gets written to the internal
    /// writer. Returns the number of bytes consumed from `buf`.
    ///
    /// If a `prefix` is provided, it will be re-applied to every frame, as tables are discarded at
    /// end of frame. Referencing a prefix involves building tables, which is a CPU consuming
    /// operation, with non-negligible impact on latency. This should be avoided for small frame
    /// sizes. If there is a need to use the same prefix multiple times without long distance mode,
    /// consider loading a dictionary into the compression context instead.
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress_with_prefix<'b: 'a>(
        &mut self,
        buf: &[u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<usize> {
        let mut input_progress = 0;

        while input_progress < buf.len() {
            let progress = self.raw.compress_with_prefix(
                &buf[input_progress..],
                &mut self.out_buf[self.out_buf_pos..],
                prefix,
            )?;

            if progress.input == 0 && progress.output == 0 {
                break;
            }

            self.out_buf_pos += progress.output;
            self.flush_out_buf(false)?;
            input_progress += progress.input;
        }

        Ok(input_progress)
    }
}

impl<W: std::io::Write> Encoder<'_, W> {
    /// Consumes and compresses input data from `buf`.
    ///
    /// Call this repetitively to consume input data. Compressed data gets written to the internal
    /// writer. Returns the number of bytes consumed from `buf`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::Encoder;
    ///
    /// let output = File::create("data.zst")?;
    /// let mut encoder = Encoder::new(output)?;
    ///
    /// encoder.compress(b"Hello, World!")?;
    /// # Ok::<(), zeekstd::Error>(())
    ///
    /// ```
    ///
    /// # Errors
    ///
    /// If compression fails or any parameter is invalid.
    pub fn compress(&mut self, buf: &[u8]) -> Result<usize> {
        self.compress_with_prefix(buf, None)
    }

    /// Ends the current frame.
    ///
    /// Call this to write the frame epilogue to the internal writer. Returns the number of bytes
    /// written.
    ///
    /// # Errors
    ///
    /// Fails if the frame epilogue cannot be written or the frame limit is reached.
    pub fn end_frame(&mut self) -> Result<usize> {
        let mut progress = 0;

        loop {
            let prog = self.raw.end_frame(&mut self.out_buf[self.out_buf_pos..])?;
            self.out_buf_pos += prog.output;
            self.flush_out_buf(false)?;
            progress += prog.output;

            if prog.left == 0 {
                return Ok(progress);
            }
        }
    }

    /// Ends the current frame and writes the seek table.
    ///
    /// Call this to write the seek table in `Foot` format to the internal writer. Returns the
    /// total number of bytes, i.e. all compressed data plus the size of the seek table,
    /// written by this `Encoder`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::Encoder;
    ///
    /// let output = File::create("data.zst")?;
    /// let mut encoder = Encoder::new(output)?;
    ///
    /// encoder.compress(b"Hello")?;
    /// encoder.finish()?;
    /// # Ok::<(), zeekstd::Error>(())
    ///
    /// ```
    ///
    /// # Errors
    ///
    /// Fails if the frame cannot be finished or writing the seek table fails.
    pub fn finish(self) -> Result<u64> {
        self.finish_format(Format::Foot)
    }

    /// Ends the current frame and writes the seek table in the given format.
    ///
    /// # Errors
    ///
    /// Fails if the frame cannot be finished or writing the seek table fails.
    pub fn finish_format(mut self, format: Format) -> Result<u64> {
        self.end_frame()?;
        let mut ser = self.raw.into_seek_table().into_format_serializer(format);

        loop {
            let n = ser.write_into(&mut self.out_buf[self.out_buf_pos..]);
            if n == 0 {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.written_compressed += self.out_buf_pos as u64;
                self.writer.flush()?;
                return Ok(self.written_compressed);
            }

            self.out_buf_pos += n;
            if self.out_buf_pos == self.out_buf.len() {
                self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
                self.written_compressed += self.out_buf_pos as u64;
                self.out_buf_pos = 0;
            }
        }
    }

    /// The total number of compressed bytes that have been written to the internal writer.
    pub fn written_compressed(&self) -> u64 {
        self.written_compressed
    }

    /// Converts this encoder into the internal [`SeekTable`].
    pub fn into_seek_table(self) -> SeekTable {
        self.raw.into_seek_table()
    }

    /// Flushes the internal output buffer, if it is filled with data, or force is true.
    #[inline]
    fn flush_out_buf(&mut self, force: bool) -> Result<()> {
        if self.out_buf_pos == self.out_buf.len() || force {
            self.writer.write_all(&self.out_buf[..self.out_buf_pos])?;
            self.written_compressed += self.out_buf_pos as u64;
            self.out_buf_pos = 0;
        }

        Ok(())
    }
}

impl<W: std::io::Write> std::io::Write for Encoder<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.compress(buf).map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_out_buf(true).map_err(std::io::Error::other)?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Cursor, Write},
    };

    use crate::tests::test_input;

    use super::*;

    #[test]
    fn raw_encoder_reset() {
        let mut encoder = RawEncoder::new().unwrap();
        let mut buf = vec![0; 1024];
        encoder.compress(b"Hello", &mut buf).unwrap();
        encoder.end_frame(&mut buf).unwrap();
        assert_eq!(encoder.seek_table().num_frames(), 1);
        let first_st = encoder.seek_table().clone();

        // Build up some frame progress to reset it later
        encoder.compress(b"Bye", &mut [0; 128]).unwrap();

        encoder.reset_frame();
        encoder.reset_seek_table();
        assert_eq!(encoder.seek_table().num_frames(), 0);

        encoder.compress(b"Hello", &mut buf).unwrap();
        encoder.end_frame(&mut buf).unwrap();
        assert_eq!(encoder.seek_table().num_frames(), 1);

        debug_assert_eq!(&first_st, encoder.seek_table());
    }

    #[test]
    fn checksum() {
        let input = fs::read(test_input()).unwrap();
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = EncodeOptions::new()
            .checksum_flag(true)
            .frame_size_policy(FrameSizePolicy::Uncompressed(input.len() as u32 / 3))
            .into_encoder(&mut seekable)
            .unwrap();

        encoder.compress(&input).unwrap();
        encoder.end_frame().unwrap();
        encoder.flush().unwrap();
        // Additional frame for remaining data
        assert_eq!(encoder.seek_table().num_frames(), 4);
        let st = encoder.into_seek_table();

        for i in 0usize..4 {
            let start_pos = st.frame_start_comp(i as u32).unwrap();
            // Get the Frame_Header_Descriptor
            let descriptor = seekable.get_ref()[start_pos as usize + 4];
            // Check that the Content_Checksum_flag is set
            assert!(descriptor & 0x4 > 0);
        }
    }
}
