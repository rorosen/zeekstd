use crate::{
    SEEK_TABLE_FOOTER_SIZE, SEEKABLE_MAGIC_NUMBER, SEEKABLE_MAX_FRAMES, SKIPPABLE_HEADER_SIZE,
    SKIPPABLE_MAGIC_NUMBER,
    error::{Error, Result},
};

// Writes a 32 bit value in little endian to buf
macro_rules! write_le32 {
    ($buf:expr, $buf_pos:expr, $write_pos:expr, $value:expr, $offset:expr) => {
        // Only write if this hasn't been written before
        if $write_pos < $offset + 4 {
            // Minimum of remaining buffer space and number of bytes we want to write
            let len = usize::min($buf.len() - $buf_pos, $offset + 4 - $write_pos);
            // The value offset, > 0 if we wrote the value partially in a previous run (because of
            // little buffer space remaining)
            let val_offset = $write_pos - $offset;
            // Copy the importnat parts of value to buf
            $buf[$buf_pos..$buf_pos + len]
                .copy_from_slice(&$value.to_le_bytes()[val_offset..val_offset + len]);
            $buf_pos += len;
            $write_pos += len;
            // Return if the buffer is full
            if $buf_pos == $buf.len() {
                return $buf_pos;
            }
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
/// let mut buffer = [0; 128];
///
/// fl.log_frame(123, 456, Some(789))?;
/// fl.write_seek_table_into(&mut buffer);
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
    pub fn write_seek_table_into(&mut self, buf: &mut [u8]) -> usize {
        let size_per_frame: usize = if self.with_checksum { 12 } else { 8 };
        let mut buf_pos = 0;

        // The total size of the seek table frame, not including the SKIPPABLE_MAGIC_NUMBER and
        // seek_table_size. Should always fit in u32.
        let seek_table_size = (size_per_frame * self.frames.len() + SEEK_TABLE_FOOTER_SIZE) as u32;
        // Serialize header
        write_le32!(buf, buf_pos, self.write_pos, SKIPPABLE_MAGIC_NUMBER, 0);
        write_le32!(buf, buf_pos, self.write_pos, seek_table_size, 4);

        // Serialize frames
        while self.frame_index < self.frames.len() {
            let frame = &self.frames[self.frame_index];
            let offset = SKIPPABLE_HEADER_SIZE + size_per_frame * self.frame_index;
            write_le32!(buf, buf_pos, self.write_pos, frame.c_size, offset);
            write_le32!(buf, buf_pos, self.write_pos, frame.d_size, offset + 4);
            if self.with_checksum {
                write_le32!(buf, buf_pos, self.write_pos, frame.checksum, offset + 8);
            }
            self.frame_index += 1;
        }

        // Serialize footer
        let pos = SKIPPABLE_HEADER_SIZE + size_per_frame * self.frames.len();
        write_le32!(
            buf,
            buf_pos,
            self.write_pos,
            // Always fit in u32 because cannot be greater than SEEKABLE_MAX_FRAMES
            self.frames.len() as u32,
            pos
        );
        let descriptor: u8 = if self.with_checksum { 1 << 7 } else { 0 };
        if self.write_pos < pos + 5 {
            buf[buf_pos] = descriptor;
            buf_pos += 1;
            self.write_pos += 1;
        }
        write_le32!(buf, buf_pos, self.write_pos, SEEKABLE_MAGIC_NUMBER, pos + 5);

        buf_pos
    }

    /// Whether the seek table gets currently written.
    pub fn is_writing_seek_table(&self) -> bool {
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
        Ok(self.write_seek_table_into(buf))
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

        fl.write_seek_table_into(&mut out1);
        assert!(fl.is_writing_seek_table());
        fl.reset_write_pos();
        assert!(!fl.is_writing_seek_table());
        fl.write_seek_table_into(&mut out2);
        fl.reset_write_pos();
        std::io::copy(&mut fl, &mut out3).unwrap();

        assert_eq!(out1, out2);
        assert_eq!(&out1, out3.get_ref());
    }
}
