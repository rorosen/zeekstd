use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, io::Write};
use zeekstd::{BytesWrapper, Decoder, Encoder};

const DICKENS: &[u8] = include_bytes!("../../assets/dickens.txt");
const OOFFICE: &[u8] = include_bytes!("../../assets/ooffice.exe");
const OSDB: &[u8] = include_bytes!("../../assets/osdb.bin");

fn decompress(dec: &mut Decoder<'_, BytesWrapper<'_>>, buf: &mut [u8]) {
    loop {
        let n = dec.decompress(buf).unwrap();
        if n == 0 {
            break;
        }
    }
}

fn decompression(c: &mut Criterion) {
    let mut dickens = vec![];
    let mut ooffice = vec![];
    let mut osdb = vec![];
    let mut buf = vec![0; zstd_safe::DCtx::out_size()];
    let mut enc_dickens = Encoder::new(&mut dickens).unwrap();
    let mut enc_ooffice = Encoder::new(&mut ooffice).unwrap();
    let mut enc_osdb = Encoder::new(&mut osdb).unwrap();

    enc_dickens.write_all(DICKENS).unwrap();
    let len_dickens = enc_dickens.finish().unwrap();
    enc_ooffice.write_all(OOFFICE).unwrap();
    let len_ooffice = enc_ooffice.finish().unwrap();
    enc_osdb.write_all(OSDB).unwrap();
    let len_osdb = enc_osdb.finish().unwrap();

    let dickens = BytesWrapper::new(&dickens[..len_dickens as usize]);
    let mut dec_dickens = Decoder::new(dickens).unwrap();
    let ooffice = BytesWrapper::new(&ooffice[..len_ooffice as usize]);
    let mut dec_ooffice = Decoder::new(ooffice).unwrap();
    let osdb = BytesWrapper::new(&osdb[..len_osdb as usize]);
    let mut dec_osdb = Decoder::new(osdb).unwrap();

    let mut group = c.benchmark_group("decompression");
    group.throughput(Throughput::Bytes(len_dickens));
    group.bench_function("dickens", |b| {
        b.iter(|| {
            decompress(black_box(&mut dec_dickens), black_box(&mut buf));
            dec_dickens.reset();
        });
    });

    group.throughput(Throughput::Bytes(len_ooffice));
    group.bench_function("ooffice", |b| {
        b.iter(|| {
            decompress(black_box(&mut dec_ooffice), black_box(&mut buf));
            dec_ooffice.reset();
        });
    });

    group.throughput(Throughput::Bytes(len_osdb));
    group.bench_function("osdb", |b| {
        b.iter(|| {
            decompress(black_box(&mut dec_osdb), black_box(&mut buf));
            dec_osdb.reset();
        });
    });
}

criterion_group!(benches, decompression);
criterion_main!(benches);
