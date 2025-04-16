use crate::{
    SEEK_TABLE_FOOTER_SIZE, SEEKABLE_MAGIC_NUMBER, SEEKABLE_MAX_FRAMES, SKIPPABLE_HEADER_SIZE,
    SKIPPABLE_MAGIC_NUMBER,
    error::{Error, Result},
};

macro_rules! write_le32 {
    ($buf:expr, $write_pos:expr, $offset:expr, $value:expr, $pos:expr) => {
        // Only write if this hasn't been written before
        if $write_pos < $pos + 4 {
            // Check if the buffer has space left
            if $offset + 4 > $buf.len() {
                return Ok($offset);
            }
            $buf[$offset..$offset + 4].copy_from_slice(&$value.to_le_bytes());
            $offset += 4;
            $write_pos += 4;
        }
    };
}

#[derive(Debug, Clone)]
struct Frame {
    c_size: u32,
    d_size: u32,
    checksum: u32,
}

/// A `FrameLog` is used to log frames and can be serialized into a seek table.
///
/// ```
/// use zeekstd::FrameLog;
///
/// // Create a FrameLog that requires checksums
/// let mut fl = FrameLog::new(true);
/// let mut seek_table = [0; 128];
///
/// fl.log_frame(123, 456, Some(789))?;
/// fl.write_seek_table_into(&mut seek_table)?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct FrameLog {
    frames: Vec<Frame>,
    with_checksum: bool,
    frame_index: usize,
    write_pos: usize,
}

impl FrameLog {
    /// Create a new, empty `FrameLog`.
    pub fn new(with_checksum: bool) -> Self {
        Self {
            frames: vec![],
            with_checksum,
            frame_index: 0,
            write_pos: 0,
        }
    }

    /// Append a new frame to this `FrameLog`.
    ///
    /// The checksum, if specified, should be the least significant 32 bits of the XXH64 hash of
    /// the uncompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the max frame number is reached, the seek table gets currently written or a
    /// required checksum is missing.
    pub fn log_frame(&mut self, c_size: u32, d_size: u32, checksum: Option<u32>) -> Result<()> {
        if self.frames.len() >= SEEKABLE_MAX_FRAMES {
            return Err(Error::frame_index_too_large());
        }

        if self.write_pos > 0 {
            return Err(Error::write_in_progress());
        }

        let checksum = if self.with_checksum {
            checksum.ok_or(Error::missing_checksum())?
        } else {
            0
        };

        let frame = Frame {
            c_size,
            d_size,
            checksum,
        };
        self.frames.push(frame);
        Ok(())
    }

    /// Get the number of frames.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Returns `true` if this `FrameLog` contains no frames.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Serialize this `FrameLog` into a seek table and write it to `buf`.
    ///
    /// Call this repetitively to fill `buf` with bytes. A nonzero return value indicates that
    /// `buf` has been filled with `n` bytes. Writing the seek table is complete when `Ok(0)` is
    /// returned.
    ///
    /// # Errors
    ///
    /// Fails if `buf` is too small to make progress.
    pub fn write_seek_table_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Cannot make progress with a buffer that small
        if buf.len() < 4 {
            return Err(Error::buffer_too_small());
        }

        let size_per_frame: usize = if self.with_checksum { 12 } else { 8 };
        let mut offset = 0;

        // The total size of the seek table frame, not including the SKIPPABLE_MAGIC_NUMBER and
        // seek_table_size. Should always fit in u32.
        let seek_table_size = (size_per_frame * self.frames.len() + SEEK_TABLE_FOOTER_SIZE) as u32;
        // Serialize header
        write_le32!(buf, self.write_pos, offset, SKIPPABLE_MAGIC_NUMBER, 0);
        write_le32!(buf, self.write_pos, offset, seek_table_size, 4);

        // Serialize frames
        while self.frame_index < self.frames.len() {
            let frame = &self.frames[self.frame_index];
            let pos = SKIPPABLE_HEADER_SIZE + size_per_frame * self.frame_index;
            write_le32!(buf, self.write_pos, offset, frame.c_size, pos);
            write_le32!(buf, self.write_pos, offset, frame.d_size, pos + 4);
            if self.with_checksum {
                write_le32!(buf, self.write_pos, offset, frame.checksum, pos + 8);
            }
            self.frame_index += 1;
        }

        // Serialize footer
        let pos = SKIPPABLE_HEADER_SIZE + size_per_frame * self.frames.len();
        write_le32!(
            buf,
            self.write_pos,
            offset,
            // Always fit in u32 because cannot be greater than SEEKABLE_MAX_FRAMES
            self.frames.len() as u32,
            pos
        );
        let descriptor: u8 = if self.with_checksum { 1 << 7 } else { 0 };
        if self.write_pos < pos + 5 {
            buf[offset] = descriptor;
            offset += 1;
            self.write_pos += 1;
        }
        write_le32!(buf, self.write_pos, offset, SEEKABLE_MAGIC_NUMBER, pos + 5);

        Ok(offset)
    }

    /// Whether the seek table gets currently written.
    pub fn is_writing(&self) -> bool {
        self.write_pos != 0
    }

    /// Resets the seek table write progress, if any.
    ///
    /// After this method has been called, the next call to `write_seek_table` starts from the
    /// beginning.
    pub fn reset_write_pos(&mut self) {
        self.write_pos = 0;
        self.frame_index = 0;
    }
}

impl std::io::Read for FrameLog {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.write_seek_table_into(buf)
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_log_with_checksum() {
        let mut fl = FrameLog::new(true);
        assert!(fl.is_empty());

        for i in 1..=16 {
            fl.log_frame(i, i, Some(i)).unwrap();
        }

        assert!(!fl.is_empty());
        assert_eq!(fl.len(), 16);
        // Cannot log frame without checksum
        assert!(fl.log_frame(2, 2, None).is_err());
    }

    #[test]
    fn frame_log_no_checksum() {
        let mut fl = FrameLog::new(false);
        assert!(fl.is_empty());
        assert!(fl.log_frame(1, 1, None).is_ok());
    }

    #[test]
    fn frame_log_write_seek_table() {
        let mut fl = FrameLog::new(true);

        for i in 1..=16 {
            fl.log_frame(i, i, Some(i)).unwrap();
        }

        let mut out1 = vec![0; 1024];
        let mut out2 = vec![0; 1024];
        let mut out3 = std::io::Cursor::new(vec![0; 1024]);

        fl.write_seek_table_into(&mut out1).unwrap();
        assert!(fl.is_writing());
        fl.reset_write_pos();
        assert!(!fl.is_writing());
        fl.write_seek_table_into(&mut out2).unwrap();
        fl.reset_write_pos();
        std::io::copy(&mut fl, &mut out3).unwrap();

        assert_eq!(out1, out2);
        assert_eq!(&out1, out3.get_ref());
    }
}
