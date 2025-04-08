use std::io::Read;

use crate::{
    SEEK_TABLE_FOOTER_SIZE, SEEKABLE_MAGIC_NUMBER, SEEKABLE_MAX_FRAMES, SKIPPABLE_HEADER_SIZE,
    SKIPPABLE_MAGIC_NUMBER,
    error::{Error, Result},
};

macro_rules! write_le32 {
    ($buf:expr, $read_pos:expr, $offset:expr, $value:expr, $pos:expr) => {
        // Only write if this hasn't been written before
        if $read_pos < $pos + 4 {
            // Check if the buffer has space left
            if $offset + 4 > $buf.len() {
                return Ok($offset);
            }
            $buf[$offset..$offset + 4].copy_from_slice(&$value.to_le_bytes());
            $offset += 4;
            $read_pos += 4;
        }
    };
}

#[derive(Debug, Clone)]
struct Frame {
    c_size: u32,
    d_size: u32,
    checksum: u32,
}

/// A `FrameLog` is used to create seek tables.
///
/// ```
/// use zeekstd::FrameLog;
///
/// let mut fl = FrameLog::new(true);
/// fl.log_frame(123, 456, Some(789))?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct FrameLog {
    frames: Vec<Frame>,
    with_checksum: bool,
}

impl FrameLog {
    /// Create a new, empty `FrameLog`.
    pub fn new(with_checksum: bool) -> Self {
        Self {
            frames: vec![],
            with_checksum,
        }
    }

    /// Add a frame to this `FrameLog`.
    ///
    /// The checksum, if speciied, should be the least significant 32 bits of the XXH64 hash of
    /// the uncompressed data.
    ///
    /// # Errors
    ///
    /// Fails if `with_checksum` was `true` at creation but checksum is `None`.
    pub fn log_frame(&mut self, c_size: u32, d_size: u32, checksum: Option<u32>) -> Result<()> {
        if self.frames.len() >= SEEKABLE_MAX_FRAMES {
            return Err(Error::frame_index_too_large());
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

    /// Returns `true` if the `FrameLog` contains no frames.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// Serialization of a [`FrameLog`].
///
/// Read this reader to get the serialized [`FrameLog`].
pub struct FrameLogReader {
    frames: Vec<Frame>,
    with_checksum: bool,
    frame_index: usize,
    read_pos: usize,
}

impl From<FrameLog> for FrameLogReader {
    fn from(value: FrameLog) -> Self {
        Self {
            frames: value.frames,
            with_checksum: value.with_checksum,
            frame_index: 0,
            read_pos: 0,
        }
    }
}

impl Read for FrameLogReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Cannot make progress with a buffer that small
        if buf.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }

        let size_per_frame: usize = if self.with_checksum { 12 } else { 8 };
        let mut offset = 0;

        // The total size of the seek table frame, not including the SKIPPABLE_MAGIC_NUMBER and
        // seek_table_size.
        let seek_table_size: u32 =
            size_per_frame as u32 * self.frames.len() as u32 + SEEK_TABLE_FOOTER_SIZE;
        // Header
        write_le32!(buf, self.read_pos, offset, SKIPPABLE_MAGIC_NUMBER, 0);
        write_le32!(buf, self.read_pos, offset, seek_table_size, 4);

        // Frames
        while self.frame_index < self.frames.len() {
            let frame = &self.frames[self.frame_index];
            let pos = SKIPPABLE_HEADER_SIZE as usize + size_per_frame * self.frame_index;
            write_le32!(buf, self.read_pos, offset, frame.c_size, pos);
            write_le32!(buf, self.read_pos, offset, frame.d_size, pos + 4);
            if self.with_checksum {
                write_le32!(buf, self.read_pos, offset, frame.checksum, pos + 8);
            }
            self.frame_index += 1;
        }

        // Footer
        let pos = SKIPPABLE_HEADER_SIZE as usize + size_per_frame * self.frames.len();
        write_le32!(buf, self.read_pos, offset, self.frames.len() as u32, pos);
        let descriptor: u8 = if self.with_checksum { 1 << 7 } else { 0 };
        if self.read_pos < pos + 5 {
            buf[offset] = descriptor;
            offset += 1;
            self.read_pos += 1;
        }
        write_le32!(buf, self.read_pos, offset, SEEKABLE_MAGIC_NUMBER, pos + 5);

        Ok(offset)
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
        assert!(fl.log_frame(2, 2, None).is_err());
    }

    #[test]
    fn frame_log_no_checksum() {
        let mut fl = FrameLog::new(false);
        assert!(fl.is_empty());
        assert!(fl.log_frame(1, 1, None).is_ok());
    }
}
