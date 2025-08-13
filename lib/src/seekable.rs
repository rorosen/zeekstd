use crate::{
    SEEK_TABLE_INTEGRITY_SIZE, SKIPPABLE_HEADER_SIZE,
    error::{Error, Result},
    seek_table::Format,
};

/// Enumeration of possible methods to set the offset within a [`Seekable`] object.
pub enum OffsetFrom {
    /// Sets the offset to the provided number of bytes.
    Start(u64),
    /// Sets the offset to the size of this object plus the specified number of bytes.
    End(i64),
}

/// Represents a seekable source.
pub trait Seekable {
    /// Sets the read offset from the start of the seekable.
    ///
    /// If successful, returns the new position from the start of the seekable.
    ///
    /// # Errors
    ///
    /// Fails if the offset cannot be set. e.g. because it is out of range.
    fn set_offset(&mut self, offset: OffsetFrom) -> Result<u64>;

    /// Pull some bytes from this source into `buf`, returning how many bytes were read.
    ///
    /// # Errors
    ///
    /// If the read operation fails.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Returns the integrity field of this seekable.
    ///
    /// # Errors
    ///
    /// Fails if the integrity field cannot be retrieved.
    fn seek_table_integrity(&mut self, format: Format) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]>;
}

/// A seekable wrapper around a byte slice.
#[derive(Debug, Clone)]
pub struct BytesWrapper<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> BytesWrapper<'a> {
    /// Returns a new `BytesWrapper` around the given slice.
    pub fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }
}

impl Seekable for BytesWrapper<'_> {
    fn set_offset(&mut self, offset: OffsetFrom) -> Result<u64> {
        let pos = match offset {
            OffsetFrom::Start(pos) => usize::try_from(pos).ok(),
            OffsetFrom::End(delta) => isize::try_from(delta)
                .map(|d| self.src.len().checked_add_signed(d))
                .ok()
                .flatten(),
        }
        .ok_or(Error::offset_out_of_range())?;

        if pos > self.src.len() {
            return Err(Error::offset_out_of_range());
        }

        self.pos = pos;

        Ok(pos as u64)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len().min(self.src.len() - self.pos);
        buf[..len].copy_from_slice(&self.src[self.pos..self.pos + len]);
        self.pos += len;

        Ok(len)
    }

    fn seek_table_integrity(&mut self, format: Format) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]> {
        let offset = match format {
            Format::Head => (self.src.len() >= SKIPPABLE_HEADER_SIZE + SEEK_TABLE_INTEGRITY_SIZE)
                .then_some(SKIPPABLE_HEADER_SIZE),
            // Last 9 bytes
            Format::Foot => self.src.len().checked_sub(SEEK_TABLE_INTEGRITY_SIZE),
        }
        .ok_or(Error::offset_out_of_range())?;

        let mut buf = [0u8; SEEK_TABLE_INTEGRITY_SIZE];
        buf.copy_from_slice(&self.src[offset..offset + SEEK_TABLE_INTEGRITY_SIZE]);

        Ok(buf)
    }
}

#[cfg(feature = "std")]
impl From<OffsetFrom> for std::io::SeekFrom {
    fn from(value: OffsetFrom) -> Self {
        use std::io::SeekFrom;

        match value {
            OffsetFrom::Start(n) => SeekFrom::Start(n),
            OffsetFrom::End(n) => SeekFrom::End(n),
        }
    }
}

#[cfg(feature = "std")]
impl<T> Seekable for T
where
    T: std::io::Read + std::io::Seek,
{
    fn set_offset(&mut self, offset: OffsetFrom) -> Result<u64> {
        Ok(self.seek(offset.into())?)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.read(buf)?)
    }

    fn seek_table_integrity(&mut self, format: Format) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]> {
        match format {
            Format::Head => self.seek(std::io::SeekFrom::Start(SKIPPABLE_HEADER_SIZE as u64))?,
            // Last 9 bytes
            Format::Foot => {
                self.seek(std::io::SeekFrom::End(-(SEEK_TABLE_INTEGRITY_SIZE as i64)))?
            }
        };

        let mut buf = [0u8; SEEK_TABLE_INTEGRITY_SIZE];
        self.read_exact(&mut buf)?;

        Ok(buf)
    }
}
