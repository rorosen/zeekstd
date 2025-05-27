use crate::{
    SEEK_TABLE_INTEGRITY_SIZE,
    error::{Error, Result},
};

/// Represents a seekable source.
pub trait Seekable {
    /// Sets the read offset from the start of the seekable.
    ///
    /// # Errors
    ///
    /// Fails if the offset cannot be set. e.g. because it is out of range.
    fn set_offset(&mut self, offset: u64) -> Result<()>;

    /// Pull some bytes from this source into `buf`, returning how many bytes were read.
    ///
    /// # Errors
    ///
    /// If the read operation fails.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Returns the footer of this seekable.
    ///
    /// The footer typically contains the integrity field of the seek table.
    ///
    /// # Errors
    ///
    /// Fails if the footer cannot be retrieved.
    fn seek_table_footer(&mut self) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]>;

    /// Seeks to the start of the seek table.
    ///
    /// # Errors
    ///
    /// Fails if `seek_table_size` is out of range.
    fn seek_to_seek_table_start(&mut self, seek_table_size: usize) -> Result<()>;
}

/// A seekable wrapper around a byte slice.
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
    fn set_offset(&mut self, offset: u64) -> Result<()> {
        let off_usize: usize = offset.try_into()?;
        if off_usize > self.src.len() {
            return Err(Error::offset_out_of_range());
        }

        self.pos = off_usize;
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let limit = buf.len().min(self.src.len() - self.pos);
        buf[..limit].copy_from_slice(&self.src[self.pos..limit]);
        self.pos += limit;

        Ok(limit)
    }

    fn seek_table_footer(&mut self) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]> {
        let mut buf = [0u8; SEEK_TABLE_INTEGRITY_SIZE];
        let start_offset = self
            .src
            .len()
            .checked_sub(SEEK_TABLE_INTEGRITY_SIZE)
            .ok_or(Error::other("invalid integrity field"))?;
        buf.copy_from_slice(&self.src[start_offset..]);

        Ok(buf)
    }

    fn seek_to_seek_table_start(&mut self, seek_table_size: usize) -> Result<()> {
        if seek_table_size > self.src.len() {
            return Err(Error::offset_out_of_range());
        }

        self.pos = self.src.len() - seek_table_size;
        Ok(())
    }
}

impl<T> Seekable for T
where
    T: std::io::Read + std::io::Seek,
{
    fn set_offset(&mut self, offset: u64) -> Result<()> {
        self.seek(std::io::SeekFrom::Start(offset))?;

        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.read(buf)?)
    }

    fn seek_table_footer(&mut self) -> Result<[u8; SEEK_TABLE_INTEGRITY_SIZE]> {
        self.seek(std::io::SeekFrom::End(-(SEEK_TABLE_INTEGRITY_SIZE as i64)))?;
        let mut buf = [0u8; SEEK_TABLE_INTEGRITY_SIZE];
        self.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn seek_to_seek_table_start(&mut self, seek_table_size: usize) -> Result<()> {
        let size: i64 = -(seek_table_size.try_into()?);
        self.seek(std::io::SeekFrom::End(size))?;

        Ok(())
    }
}
