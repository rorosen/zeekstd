use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, io::Write};
use zeekstd::{EncodeOptions, Encoder, RawEncoder};

const DICKENS: &[u8] = include_bytes!("../../assets/dickens.txt");
const OOFFICE: &[u8] = include_bytes!("../../assets/ooffice.exe");
const OSDB: &[u8] = include_bytes!("../../assets/osdb.bin");

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

fn compress(enc: &mut Encoder<'_, Vec<u8>>, input: &[u8]) {
    enc.write_all(input).unwrap();
    enc.end_frame().unwrap();
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

    group.throughput(Throughput::Bytes(OOFFICE.len() as u64));
    group.bench_function("ooffice", |b| {
        b.iter(|| {
            raw_compress(&mut enc, black_box(OOFFICE), black_box(&mut output));
        });
    });

    group.throughput(Throughput::Bytes(OSDB.len() as u64));
    group.bench_function("osdb", |b| {
        b.iter(|| {
            raw_compress(&mut enc, black_box(OSDB), black_box(&mut output));
        });
    });

    group.finish();
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

    group.throughput(Throughput::Bytes(OOFFICE.len() as u64));
    group.bench_function("ooffice", |b| {
        b.iter(|| {
            compress(&mut enc, black_box(OOFFICE));
        });
    });

    group.throughput(Throughput::Bytes(OSDB.len() as u64));
    group.bench_function("osdb", |b| {
        b.iter(|| {
            compress(&mut enc, black_box(OSDB));
        });
    });

    group.finish();
}

criterion_group!(benches, raw_compression, compression);
criterion_main!(benches);
