use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, io::Write};
use zeekstd::{EncodeOptions, Encoder, RawEncoder};
use zstd::stream::raw::Operation;

const DICKENS: &[u8] = include_bytes!("../../assets/dickens.txt");

fn raw_compress(enc: &mut RawEncoder, input: &[u8], output: &mut [u8]) {
    let mut in_prog = 0;

    while in_prog != input.len() {
        let prog = enc.compress(&input[in_prog..], output).unwrap();
        in_prog += prog.in_progress();
    }

    loop {
        let prog = enc.end_frame(output).unwrap();
        if prog.data_left() == 0 {
            break;
        }
    }
}

fn raw_compression(c: &mut Criterion) {
    let mut enc = EncodeOptions::new()
        .compression_level(1)
        .into_raw_encoder()
        .unwrap();
    let mut output = vec![0; zstd_safe::CCtx::out_size()];

    let mut group = c.benchmark_group("raw_compression");
    group.throughput(Throughput::Bytes(DICKENS.len() as u64));
    group.bench_function("dickens", |b| {
        b.iter(|| {
            raw_compress(&mut enc, black_box(DICKENS), black_box(&mut output));
        });
    });

    group.finish();
}

fn compress(enc: &mut Encoder<'_, Vec<u8>>, input: &[u8]) {
    enc.write_all(input).unwrap();
    enc.end_frame().unwrap();
}

fn compression(c: &mut Criterion) {
    let mut enc = EncodeOptions::new()
        .compression_level(1)
        .into_encoder(Vec::new())
        .unwrap();

    let mut group = c.benchmark_group("compression");
    group.throughput(Throughput::Bytes(DICKENS.len() as u64));
    group.bench_function("dickens", |b| {
        b.iter(|| {
            compress(&mut enc, black_box(DICKENS));
        });
    });

    group.finish();
}

fn zstd_rs_compress(enc: &mut zstd::stream::raw::Encoder, input: &[u8], output: &mut [u8]) {
    let mut in_prog = 0;

    while in_prog != input.len() {
        let stat = enc.run_on_buffers(&input[in_prog..], output).unwrap();
        in_prog += stat.bytes_read;
    }

    loop {
        let mut out_buffer = zstd_safe::OutBuffer::around(output);
        let n = enc.finish(&mut out_buffer, false).unwrap();
        if n == 0 {
            break;
        }
    }
}

fn zstd_rs_compression(c: &mut Criterion) {
    let mut enc = zstd::stream::raw::Encoder::new(1).unwrap();
    let mut group = c.benchmark_group("zstd_rs_compression");
    let mut output = vec![0; zstd_safe::CCtx::out_size()];

    group.throughput(Throughput::Bytes(DICKENS.len() as u64));
    group.bench_function("dickens", |b| {
        b.iter(|| {
            zstd_rs_compress(&mut enc, black_box(DICKENS), black_box(&mut output));
        });
    });

    group.finish();
}

criterion_group!(benches, raw_compression, compression, zstd_rs_compression,);
criterion_main!(benches);
