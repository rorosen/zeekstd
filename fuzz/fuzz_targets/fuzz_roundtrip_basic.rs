#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{Read, Write};
use zeekstd::{BytesWrapper, Decoder, EncodeOptions};

fuzz_target!(|data: &[u8]| {
    let mut compressed: Vec<u8> = Vec::new();
    {
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(zeekstd::FrameSizePolicy::Uncompressed(100))
            .into_encoder(&mut compressed)
            .unwrap();
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
    }

    let mut decoder = Decoder::new(BytesWrapper::new(&compressed)).unwrap();
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();

    assert_eq!(data, &decompressed);
});
