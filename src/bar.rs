use std::io::Read;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

pub struct Bar(ProgressBar);

impl Bar {
    pub fn new(input_len: Option<u64>) -> Self {
        let bar = ProgressBar::with_draw_target(input_len, ProgressDrawTarget::stderr_with_hz(5))
            .with_style(
                ProgressStyle::with_template("Read {binary_bytes} of {binary_total_bytes}")
                    .expect("Static template always works"),
            );

        Self(bar)
    }

    // TODO: remove use<...> bound in rust 2024
    pub fn as_reader<R: Read>(&self, reader: R) -> impl Read + use<'_, R> {
        BarReader {
            bar: &self.0,
            reader,
        }
    }
}

struct BarReader<'a, R> {
    bar: &'a ProgressBar,
    reader: R,
}

impl<R: Read> Read for BarReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.bar.inc(n as u64);

        Ok(n)
    }
}
