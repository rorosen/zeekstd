use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, io::Write};
use zeekstd::{BytesWrapper, Decoder, Encoder};

const DICKENS: &[u8] = include_bytes!("../../assets/dickens.txt");

fn dickens_compressed() -> Vec<u8> {
    let mut buf = vec![];
    let mut enc = Encoder::new(&mut buf).unwrap();

    enc.write_all(DICKENS).unwrap();
    enc.finish().unwrap();

    buf
}

fn decompress(dec: &mut Decoder<'_, BytesWrapper<'_>>, buf: &mut [u8]) {
    loop {
        let n = dec.decompress(buf).unwrap();
        if n == 0 {
            break;
        }
    }
}

fn decompression(c: &mut Criterion) {
    let mut buf = vec![0; zstd_safe::DCtx::out_size()];

    let comp = dickens_compressed();
    let mut dec = Decoder::new(BytesWrapper::new(&comp)).unwrap();

    let mut group = c.benchmark_group("decompression");
    group.throughput(Throughput::Bytes(DICKENS.len() as u64));
    group.bench_function("dickens", |b| {
        b.iter(|| {
            decompress(&mut dec, black_box(&mut buf));
            dec.reset();
        });
    });
}

criterion_group!(benches, decompression);
criterion_main!(benches);
