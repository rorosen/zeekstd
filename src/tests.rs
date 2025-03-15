use std::{
    io::{self, Cursor, Read, Seek, Write},
    path::PathBuf,
    str::FromStr,
};

use crate::{
    args::{ByteOffset, ByteValue, CompressArgs, DecompressArgs},
    compress::Compressor,
    decompress::Decompressor,
};

const INPUT: &[u8] = br#"
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt
    ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in
    reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur
    sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id
    est laborum.
"#;

fn new_decompressor<F: Read + Seek>(src: F, start: &str, end: &str) -> Decompressor<'static, F> {
    let args = DecompressArgs {
        from: ByteOffset::from_str(start).unwrap(),
        from_frame: None,
        to: ByteOffset::from_str(end).unwrap(),
        to_frame: None,
        input_file: PathBuf::new(),
        output_file: None,
    };

    Decompressor::new(src, &args).unwrap()
}

#[test]
fn cycle() {
    let mut input = Cursor::new(INPUT);
    let compressed = Cursor::new(vec![0u8; 512]);
    let compress_args = CompressArgs {
        compression_level: 3,
        no_checksum: false,
        max_frame_size: ByteValue::from_str("128B").unwrap(),
        input_file: PathBuf::new(),
        output_file: None,
    };
    let mut compressor = Compressor::new(&compress_args, compressed).unwrap();

    io::copy(&mut input, &mut compressor).unwrap();
    compressor.flush().unwrap();

    let mut compressed = compressor.into_out();
    let pos = compressed.position() as usize;
    compressed.get_mut().truncate(pos);

    let mut restored = Cursor::new(std::vec![0u8; INPUT.len()]);
    let mut decompressor = new_decompressor(compressed.clone(), "start", "end");
    let written = io::copy(&mut decompressor, &mut restored).unwrap();
    assert_eq!(written, INPUT.len() as u64);
    assert_eq!(restored.get_ref(), INPUT);

    let mut mollit = Cursor::new(vec![0u8, 6]);
    let mut decompressor = new_decompressor(compressed.clone(), "439", "445");
    io::copy(&mut decompressor, &mut mollit).unwrap();
    assert_eq!(mollit.get_ref(), b"mollit");

    let mut elit = Cursor::new(vec![0u8, 4]);
    let mut decompressor = new_decompressor(compressed.clone(), "56", "60");
    io::copy(&mut decompressor, &mut elit).unwrap();
    assert_eq!(elit.get_mut(), b"elit");

    let mut consequat = Cursor::new(vec![0u8, 8]);
    let mut decompressor = new_decompressor(compressed.clone(), "234", "243");
    io::copy(&mut decompressor, &mut consequat).unwrap();
    assert_eq!(consequat.get_ref(), b"consequat");
}
