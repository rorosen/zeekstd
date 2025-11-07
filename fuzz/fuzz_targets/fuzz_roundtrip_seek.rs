#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{Read, Write};
use zeekstd::{BytesWrapper, Decoder, EncodeOptions};

fuzz_target!(|data: &[u8]| {
    let (offset0, data) = if let Some(x) = data.split_at_checked(4) {
        x
    } else {
        return;
    };
    let offset0 = u32::from_le_bytes(offset0.try_into().unwrap()) as usize;
    let (offset1, data) = if let Some(x) = data.split_at_checked(4) {
        x
    } else {
        return;
    };
    let offset1 = u32::from_le_bytes(offset1.try_into().unwrap()) as usize;
    if data.is_empty() {
        return;
    }

    let mut compressed: Vec<u8> = Vec::new();
    {
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(zeekstd::FrameSizePolicy::Uncompressed(100))
            .into_encoder(&mut compressed)
            .unwrap();
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
    }

    for offset in [offset0, offset1] {
        let offset = offset % data.len();
        let mut decoder = Decoder::new(BytesWrapper::new(&compressed)).unwrap();
        decoder.set_offset(offset as u64).unwrap();
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(&data[offset..], &decompressed);
    }
});
