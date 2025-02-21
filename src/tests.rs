use std::io::Cursor;

use crate::{compress::Compressor, decompress::Decompressor};

const INPUT: &[u8] = br#"
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt
    ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in
    reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur
    sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id
    est laborum.
"#;

#[test]
fn cycle() {
    let mut input = Cursor::new(INPUT);
    let mut compressed = Cursor::new(vec![0u8; 512]);
    let mut compressor = Compressor::new(3, true, 128).unwrap();

    compressor
        .compress_reader(&mut input, &mut compressed, &None)
        .unwrap();
    let pos = compressed.position() as usize;
    compressed.get_mut().truncate(pos);

    let mut decompressor = Decompressor::new(Box::new(compressed)).unwrap();
    assert_eq!(decompressor.num_frames(), 4);

    let mut restored = Cursor::new(std::vec![0u8; INPUT.len()]);
    decompressor
        .decompress(&mut restored, 0, u64::MAX, &None)
        .unwrap();
    assert_eq!(restored.get_ref(), INPUT);

    let mut mollit = Cursor::new(vec![0u8, 6]);
    decompressor
        .decompress(&mut mollit, 439, 445, &None)
        .unwrap();
    assert_eq!(mollit.get_ref(), b"mollit");

    let mut elit = Cursor::new(vec![0u8, 4]);
    decompressor.decompress(&mut elit, 56, 60, &None).unwrap();
    assert_eq!(elit.get_mut(), b"elit");

    let mut consequat = Cursor::new(vec![0u8, 8]);
    decompressor
        .decompress(&mut consequat, 234, 243, &None)
        .unwrap();
    assert_eq!(consequat.get_ref(), b"consequat");
}
