use zstd_safe::{DCtx, InBuffer, OutBuffer, ResetDirective};

use crate::{error::Result, seek_table::SeekTable, seekable::Seekable};

/// Options that configure how data is decompressed.
///
/// # Examples
///
/// Supports builder like chaining.
///
/// ```no_run
/// use std::fs::File;
/// use zeekstd::{DecodeOptions, FrameSizePolicy};
///
/// let mut seekable = File::open("seekable.zst")?;
/// let decoder = DecodeOptions::new(&mut seekable)
///     .lower_frame(2)
///     .upper_frame(6)
///     .into_decoder()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct DecodeOptions<'a, S> {
    dctx: DCtx<'a>,
    src: S,
    seek_table: Option<SeekTable>,
    lower_frame: Option<u32>,
    upper_frame: Option<u32>,
}

impl<'a, S> DecodeOptions<'a, S> {
    /// Creates a set of options with default initial values.
    ///
    /// # Panics
    ///
    /// If allocation of [`DCtx`] fails.
    pub fn new(src: S) -> Self {
        Self::with_dctx(src, DCtx::create())
    }

    /// Tries to create new options.
    ///
    /// Returns `None` if allocation of [`DCtx`] fails.
    pub fn try_new(src: S) -> Option<Self> {
        let dctx = DCtx::try_create()?;
        Some(Self::with_dctx(src, dctx))
    }

    /// Create options with the given decompression context.
    pub fn with_dctx(src: S, dctx: DCtx<'a>) -> Self {
        Self {
            dctx,
            src,
            seek_table: None,
            lower_frame: None,
            upper_frame: None,
        }
    }

    /// Sets a [`DCtx`].
    pub fn dctx(mut self, dctx: DCtx<'a>) -> Self {
        self.dctx = dctx;
        self
    }

    /// Sets the [`SeekTable`] for this options.
    ///
    /// If a seek table is set, it will be used directly during decompression instead of reading
    /// the seek table from the seekable `src`.
    pub fn seek_table(mut self, seek_table: SeekTable) -> Self {
        self.seek_table = Some(seek_table);
        self
    }

    /// Sets the frame where decompression starts.
    pub fn lower_frame(mut self, index: u32) -> Self {
        self.lower_frame = Some(index);
        self
    }

    /// Sets the last frame that is included in decompression.
    pub fn upper_frame(mut self, index: u32) -> Self {
        self.upper_frame = Some(index);
        self
    }
}

impl<'a, S: Seekable> DecodeOptions<'a, S> {
    /// Builds a [`Decoder`] with the configuration.
    pub fn into_decoder(self) -> Result<Decoder<'a, S>> {
        Decoder::with_opts(self)
    }
}

/// Decompresses data from a seekable source.
///
/// A decoder reads compressed data from a seekable source.
pub struct Decoder<'a, S> {
    dctx: DCtx<'a>,
    seek_table: SeekTable,
    src: S,
    src_pos: u64,
    lower_frame: u32,
    upper_frame: u32,
    in_buf: Vec<u8>,
    in_buf_pos: usize,
    in_buf_limit: usize,
    read_compressed: u64,
}

impl<'a, S: Seekable> Decoder<'a, S> {
    /// Creates a new `Decoder` with default parameters and `src` as source.
    ///
    /// This is equivalent to calling `DecodeOptions::new(src).into_decoder()`.
    pub fn new(src: S) -> Result<Self> {
        Self::with_opts(DecodeOptions::new(src))
    }

    /// Creates a new `Decoder` with the given [`DecodeOptions`].
    pub fn with_opts(mut opts: DecodeOptions<'a, S>) -> Result<Self> {
        let seek_table = opts
            .seek_table
            .map_or_else(|| SeekTable::from_seekable(&mut opts.src), Ok)?;
        let lower_frame = opts.lower_frame.unwrap_or(0);
        let upper_frame = opts
            .upper_frame
            // Make sure overflowing sub doesn't happen when num_frames() == 0
            .unwrap_or_else(|| seek_table.num_frames().max(1) - 1);

        Ok(Self {
            dctx: opts.dctx,
            seek_table,
            src: opts.src,
            src_pos: 0,
            lower_frame,
            upper_frame,
            in_buf: vec![0; DCtx::in_size()],
            in_buf_pos: 0,
            in_buf_limit: 0,
            read_compressed: 0,
        })
    }

    /// Decompresses data from the internal source.
    ///
    /// Call this repetetively to fill `buf` with decompressed data. Returns the number of bytes
    /// written to `buf`.
    ///
    /// If a `prefix` is passed, it will be re-applied to every frame, as tables are discarded at
    /// end of frame. Referencing a raw content prefix has almost no cpu nor memory cost.
    pub fn decompress_with_prefix<'b: 'a>(
        &mut self,
        buf: &mut [u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<usize> {
        let end_pos = self.seek_table.frame_end_comp(self.upper_frame)?;
        if self.src_pos == 0 {
            let start_pos = self.seek_table.frame_start_comp(self.lower_frame)?;
            self.src.set_offset(start_pos)?;
            self.src_pos = start_pos;
            // Reference prefix at the beginning of decompression
            if let Some(pref) = prefix {
                self.dctx.ref_prefix(pref)?;
            }
        }

        let mut output_progress = 0;
        while self.src_pos < end_pos && output_progress < buf.len() {
            if self.in_buf_pos == self.in_buf_limit {
                // Casting is ok because max value is buf.len()
                let limit = (end_pos - self.src_pos).min(self.in_buf.len() as u64) as usize;
                self.in_buf_limit = self.src.read(&mut self.in_buf[..limit])?;
                self.in_buf_pos = 0;
            }

            let mut in_buffer = InBuffer::around(&self.in_buf[self.in_buf_pos..self.in_buf_limit]);
            let mut out_buffer = OutBuffer::around(&mut buf[output_progress..]);

            let in_len = self.in_buf_limit - self.in_buf_pos;
            while in_buffer.pos() < in_len && out_buffer.pos() < out_buffer.capacity() {
                let n = self
                    .dctx
                    .decompress_stream(&mut out_buffer, &mut in_buffer)?;
                // Frame end
                // TODO: chain when stable
                if n == 0 {
                    if let Some(pref) = prefix {
                        self.dctx
                            .reset(ResetDirective::SessionOnly)
                            .expect("Resetting session never fails");
                        self.dctx.ref_prefix(pref)?;
                    }
                }
            }

            self.src_pos += in_buffer.pos() as u64;
            self.in_buf_pos += in_buffer.pos();
            self.read_compressed += in_buffer.pos() as u64;
            output_progress += out_buffer.pos();
        }

        Ok(output_progress)
    }
}

impl<S: Seekable> Decoder<'_, S> {
    /// Decompresses data from the internal source.
    ///
    /// Call this repetetively to fill `buf` with decompressed data. Returns the number of bytes
    /// written to `buf`.
    pub fn decompress(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.decompress_with_prefix(buf, None)
    }

    /// Resets the current decompresion status.
    pub fn reset(&mut self) {
        self.dctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");
        self.src_pos = 0;
        self.in_buf_pos = 0;
        self.in_buf_limit = 0;
        self.read_compressed = 0;
    }

    /// Sets the index of the frame where decompression starts.
    ///
    /// Also resets the current decompression state.
    pub fn set_lower_frame(&mut self, index: u32) {
        self.reset();
        self.lower_frame = index;
    }

    /// Sets the index of the last frame that is included in decompression.
    ///
    /// This does not reset the current decompression state, it is possible to change the upper
    /// frame in the middle of a decompression operation.
    pub fn set_upper_frame(&mut self, index: u32) {
        self.upper_frame = index;
    }

    /// Gets the total number of compressed bytes read since the last reset.
    pub fn read_compressed(&self) -> u64 {
        self.read_compressed
    }

    /// Returns a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.seek_table
    }
}

impl<S: Seekable> std::io::Read for Decoder<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decompress(buf).map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, Cursor};

    use crate::{
        EncodeOptions, FrameSizePolicy,
        tests::{LINE_LEN, LINES_IN_DOC, generate_input},
    };

    use super::*;

    #[test]
    fn partly_decompression() {
        const LINES_IN_FRAME: u32 = 1143;

        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(FrameSizePolicy::Uncompressed(LINE_LEN * LINES_IN_FRAME))
            .into_encoder(&mut seekable)
            .unwrap();

        // Compress the input
        io::copy(&mut input, &mut encoder).unwrap();
        let n = encoder.finish().unwrap();
        assert_eq!(n, seekable.position());

        let mut decoder = Decoder::new(seekable).unwrap();

        // Add one for the last frame
        let num_frames = LINES_IN_DOC / LINES_IN_FRAME + 1;
        assert_eq!(num_frames, decoder.seek_table().num_frames());

        let mut output = Cursor::new(vec![]);
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);

        let mut num_line = 0;
        for line in output.clone().lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);
        assert_eq!(input.get_ref(), output.get_ref());

        // Decompress until frame 6 (inclusive)
        decoder.set_lower_frame(0);
        decoder.set_upper_frame(6);
        // Dummy decompression so we can reset something
        decoder.decompress(&mut [0; 1024]).unwrap();
        decoder.reset();
        // Real decompression
        let mut output = Cursor::new(vec![]);
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);
        let mut num_line = 0;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, 7 * LINES_IN_FRAME);

        // Decompress the last 13 frames
        decoder.set_lower_frame(num_frames - 14);
        decoder.set_upper_frame(num_frames - 1);
        let mut output = Cursor::new(vec![]);
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);
        let mut num_line = (num_frames - 14) * LINES_IN_FRAME;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);

        // Start frame greater end frame, expect zero bytes read
        decoder.set_lower_frame(9);
        decoder.set_upper_frame(8);
        let mut output = Cursor::new(vec![]);
        let n = io::copy(&mut decoder, &mut output).unwrap();
        assert_eq!(0, n);
        output.set_position(0);
        assert_eq!(0, output.lines().collect::<Vec<_>>().len());

        // Start frame index too large
        decoder.set_lower_frame(num_frames);
        let mut output = Cursor::new(vec![]);
        assert!(io::copy(&mut decoder, &mut output).is_err());

        // End frame index too large
        decoder.set_lower_frame(0);
        decoder.set_upper_frame(num_frames);
        let mut output = Cursor::new(vec![]);
        assert!(io::copy(&mut decoder, &mut output).is_err());

        // Decompress all frames
        decoder.set_upper_frame(num_frames - 1);
        let mut output = Cursor::new(vec![]);
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);

        let mut num_line = 0;
        for line in output.clone().lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);
        assert_eq!(input.get_ref(), output.get_ref());
    }
}
