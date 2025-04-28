use core::ops::Deref;

use zstd_safe::{DCtx, InBuffer, OutBuffer, ResetDirective};

use crate::{error::Result, seek_table::SeekTable, seekable::Seekable};

pub struct DecodeOptions<'a, S> {
    dctx: DCtx<'a>,
    src: S,
    seek_table: Option<SeekTable>,
    lower_frame: Option<u32>,
    upper_frame: Option<u32>,
}

impl<'a, S> DecodeOptions<'a, S> {
    pub fn new(src: S) -> Self {
        Self::with_dctx(src, DCtx::create())
    }

    pub fn try_new(src: S) -> Option<Self> {
        let dctx = DCtx::try_create()?;
        Some(Self::with_dctx(src, dctx))
    }

    pub fn with_dctx(src: S, dctx: DCtx<'a>) -> Self {
        Self {
            dctx,
            src,
            seek_table: None,
            lower_frame: None,
            upper_frame: None,
        }
    }

    pub fn dctx(mut self, dctx: DCtx<'a>) -> Self {
        self.dctx = dctx;
        self
    }

    pub fn seek_table(mut self, seek_table: SeekTable) -> Self {
        self.seek_table = Some(seek_table);
        self
    }

    pub fn lower_frame(mut self, index: u32) -> Self {
        self.lower_frame = Some(index);
        self
    }

    pub fn upper_frame(mut self, index: u32) -> Self {
        self.upper_frame = Some(index);
        self
    }
}

impl<'a, S: Seekable> DecodeOptions<'a, S> {
    pub fn into_decoder(self) -> Result<Decoder<'a, S>> {
        Decoder::with_opts(self)
    }
}

/// Decompresses data from a seekable source.
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
    pub fn new(src: S) -> Result<Self> {
        Self::with_opts(DecodeOptions::new(src))
    }

    pub fn with_opts(mut opts: DecodeOptions<'a, S>) -> Result<Self> {
        let seek_table = opts
            .seek_table
            .map_or_else(|| SeekTable::from_seekable(&mut opts.src), Ok)?;
        let lower_frame = opts.lower_frame.unwrap_or(0);
        // Make sure overflowing sub doesn't happen when num_frames() == 0
        let upper_frame = opts
            .upper_frame
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
                        // TODO: reset required?
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
    /// Decompresses data from the internal source and writes it to `buf`.
    ///
    /// Call this repetitively to decompress data. Returns the number of bytes written to `buf`.
    pub fn decompress(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.decompress_with_prefix(buf, None)
    }

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
    /// This does not reset the current decompression state, so it is possible to change the upper
    /// frame in the middle of a decompression operation.
    pub fn set_upper_frame(&mut self, index: u32) {
        self.upper_frame = index;
    }

    /// Gets the total number of compressed bytes read since the last reset.
    pub fn read_compressed(&self) -> u64 {
        self.read_compressed
    }
}

impl<S> Deref for Decoder<'_, S> {
    type Target = SeekTable;

    fn deref(&self) -> &Self::Target {
        &self.seek_table
    }
}

impl<S: Seekable> std::io::Read for Decoder<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decompress(buf).map_err(std::io::Error::other)
    }
}

// /// Decompresses data from a seekable source.
// pub struct Decoder<'a, 'b, S> {
//     raw: RawDecoder<'a, 'b>,
//     seek_table: SeekTable,
//     src: S,
//     src_pos: u64,
//     lower_frame: u32,
//     upper_frame: u32,
//     in_buf: Vec<u8>,
//     in_buf_pos: usize,
//     in_buf_limit: usize,
//     read_uncompressed: u64,
// }
//
// impl<S: Seekable> Decoder<'_, '_, S> {
//     /// Creates a new `Decoder` with default parameters and `src` as source.
//     pub fn from_seekable(src: S) -> Result<Self> {
//         DecodeOptions::new().into_decoder(src)
//     }
//
//     /// Creates a new `Decoder` with default parameters and a slice as source.
//     ///
//     /// The slice needs to hold the complete seekable data, including the seek table.
//     pub fn from_bytes(src: &[u8]) -> Result<Decoder<'_, '_, BytesWrapper<'_>>> {
//         let wrapper = BytesWrapper::new(src);
//         DecodeOptions::new().into_decoder(wrapper)
//     }
// }
//
// impl<'a, 'b, S> Decoder<'a, 'b, S>
// where
//     S: Seekable,
//     'b: 'a,
// {
//     /// Decompresses data from the internal source and writes it to `buf`.
//     ///
//     /// Call this repetitively to decompress data. Returns the number of bytes written to `buf`.
//     pub fn decode(&mut self, buf: &mut [u8]) -> Result<usize> {
//         let end_pos = self.seek_table.frame_end_comp(self.upper_frame)?;
//         if self.src_pos == 0 {
//             let start_pos = self.seek_table.frame_start_comp(self.lower_frame)?;
//             self.src.set_offset(start_pos)?;
//             self.src_pos = start_pos;
//             self.raw.reset_frame()?;
//         }
//
//         let mut output_progress = 0;
//         while self.src_pos < end_pos && output_progress < buf.len() {
//             if self.in_buf_pos == self.in_buf_limit {
//                 // Casting is ok because max value is buf.len()
//                 let limit = (end_pos - self.src_pos).min(self.in_buf.len() as u64) as usize;
//                 self.in_buf_limit = self.src.read(&mut self.in_buf[..limit])?;
//                 self.in_buf_pos = 0;
//             }
//
//             let (inp_prog, out_prog) = self.raw.decompress_with_seek_table(
//                 &self.seek_table,
//                 self.src_pos,
//                 &self.in_buf[self.in_buf_pos..self.in_buf_limit],
//                 &mut buf[output_progress..],
//             )?;
//
//             self.src_pos += inp_prog as u64;
//             self.in_buf_pos += inp_prog;
//             self.read_uncompressed += inp_prog as u64;
//             output_progress += out_prog;
//         }
//         Ok(output_progress)
//     }
//
//     /// Resets the current frame.
//     ///
//     /// This will discard any decompression progress tracked for the current frame and resets
//     /// the decompression context.
//     pub fn reset_frame(&mut self) -> Result<()> {
//         self.raw.reset_frame()?;
//         self.src_pos = 0;
//         self.in_buf_pos = 0;
//         self.in_buf_limit = 0;
//
//         Ok(())
//     }
//
//     /// Sets the index of the frame where decompression starts.
//     ///
//     /// Resets the current frame decompression progress, this shouldn't be called in the middle of
//     /// a decompression operation.
//     pub fn set_lower_frame(&mut self, index: u32) -> Result<()> {
//         self.lower_frame = index;
//         self.reset_frame()?;
//
//         Ok(())
//     }
//
//     /// Sets the index of the last frame that is included in decompression.
//     pub fn set_upper_frame(&mut self, index: u32) {
//         self.upper_frame = index;
//     }
//
//     /// Gets the total number of uncompressed bytes read until now.
//     pub fn read_uncompressed(&self) -> u64 {
//         self.read_uncompressed
//     }
// }
//
// impl<S> Deref for Decoder<'_, '_, S> {
//     type Target = SeekTable;
//
//     fn deref(&self) -> &Self::Target {
//         &self.seek_table
//     }
// }
//
// impl<'a, 'b, S> std::io::Read for Decoder<'a, 'b, S>
// where
//     S: Seekable,
//     'b: 'a,
// {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         self.decode(buf).map_err(std::io::Error::other)
//     }
// }
