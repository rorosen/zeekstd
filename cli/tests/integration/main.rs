use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use assert_cmd::{Command, cargo::cargo_bin_cmd};
use tempfile::{NamedTempFile, TempDir};

const FRAME_SIZES: [&str; 5] = ["10", "123", "3K", "2M", "1G"];

fn test_input() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../assets/dickens.txt")
}

fn compress_test_input(out_path: &Path, frame_size: &str) {
    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--output-file")
        .arg(out_path)
        .arg("--frame-size")
        .arg(frame_size)
        .write_stdin("y")
        .assert()
        .success();
}

fn verify_compressed_file(path: &Path) {
    let output = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(path)
        .arg("--output-file")
        .arg(output.path())
        .write_stdin("y")
        .assert()
        .success();

    assert_eq!(
        fs::read(test_input()).unwrap(),
        fs::read(output.path()).unwrap()
    );
}

fn test_cycle(frame_size: &str) {
    let compressed = NamedTempFile::new().unwrap();

    compress_test_input(compressed.path(), frame_size);
    verify_compressed_file(compressed.path());
}

fn test_cycle_stdin(frame_size: &str) {
    let dir = TempDir::new().unwrap();
    let compressed_path = dir.path().join("test.zst");

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg("--output-file")
        .arg(&compressed_path)
        .arg("--frame-size")
        .arg(frame_size)
        .write_stdin(fs::read(test_input()).unwrap())
        .assert()
        .success();

    verify_compressed_file(&compressed_path);
}

fn test_cycle_stdout(frame_size: &str) {
    let out = cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--stdout")
        .arg("--frame-size")
        .arg(frame_size)
        .write_stdin("y")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let mut compressed = NamedTempFile::new().unwrap();
    compressed.write_all(&out).unwrap();

    verify_compressed_file(compressed.path());
}

fn test_cycle_stdin_to_stdout(frame_size: &str) {
    let out = cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg("--stdout")
        .arg("--frame-size")
        .arg(frame_size)
        .write_stdin(fs::read(test_input()).unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let mut compressed = NamedTempFile::new().unwrap();
    compressed.write_all(&out).unwrap();

    verify_compressed_file(compressed.path());
}

fn test_cycle_with_separate_seek_table(frame_size: &str) {
    let dir = TempDir::new().unwrap();
    let compressed_path = dir.path().join("seekable.zst");
    let seek_table_path = dir.path().join("seek_table");

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--output-file")
        .arg(&compressed_path)
        .arg("--frame-size")
        .arg(frame_size)
        .arg("--seek-table-file")
        .arg(&seek_table_path)
        .assert()
        .success();

    let decompressed = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(&compressed_path)
        .arg("--seek-table-file")
        .arg(&seek_table_path)
        .arg("--output-file")
        .arg(decompressed.path())
        .write_stdin("y")
        .assert()
        .success();

    assert_eq!(
        fs::read(test_input()).unwrap(),
        fs::read(decompressed.path()).unwrap()
    );
}

#[test]
fn cycle() {
    for frame_size in FRAME_SIZES {
        test_cycle(frame_size);
    }
}

#[test]
fn cycle_stdin() {
    for frame_size in FRAME_SIZES {
        test_cycle_stdin(frame_size);
    }
}

#[test]
fn cycle_stdout() {
    for frame_size in FRAME_SIZES {
        test_cycle_stdout(frame_size);
    }
}

#[test]
fn cycle_stdin_to_stdout() {
    for frame_size in FRAME_SIZES {
        test_cycle_stdin_to_stdout(frame_size);
    }
}

#[test]
fn cycle_with_separate_seek_table() {
    for frame_size in FRAME_SIZES {
        test_cycle_with_separate_seek_table(frame_size);
    }
}

#[test]
fn derive_out_name() {
    let dir = TempDir::new().unwrap();
    let mut input = NamedTempFile::new_in(dir.path()).unwrap();
    input.write_all(b"foo").unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(input.path())
        .assert()
        .success();

    assert!(PathBuf::from(format!("{}.zst", input.path().display())).exists());
}

#[test]
fn do_not_overwrite_existing_output_file() {
    let output = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--output-file")
        .arg(output.path())
        .assert()
        .failure();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg("--output-file")
        .arg(output.path())
        .write_stdin(fs::read(test_input()).unwrap())
        .assert()
        .failure();
}

#[test]
fn do_not_overwrite_existing_seek_table_file() {
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("bar.zst");
    let seek_table = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--output-file")
        .arg(&out_path)
        .arg("--seek-table-file")
        .arg(seek_table.path())
        .assert()
        .failure();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg("--output-file")
        .arg(&out_path)
        .arg("--seek-table-file")
        .arg(seek_table.path())
        .write_stdin(fs::read(test_input()).unwrap())
        .assert()
        .failure();
}

#[test]
fn force_overwrite_existing_file() {
    let output = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--output-file")
        .arg(output.path())
        .arg("--force")
        .assert()
        .success();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg("--output-file")
        .arg(output.path())
        .arg("--force")
        .write_stdin(fs::read(test_input()).unwrap())
        .assert()
        .success();
}

#[test]
fn do_not_create_out_file_if_input_file_does_not_exist() {
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("bar.zst");

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(dir.path().join("foo"))
        .arg("--output-file")
        .arg(&out_path)
        .assert()
        .failure();

    assert!(!out_path.exists());
}

#[test]
fn decompress_frames() {
    let frame_size = fs::metadata(test_input()).unwrap().len() / 6;
    let seekable = NamedTempFile::new().unwrap();
    compress_test_input(seekable.path(), &frame_size.to_string());

    let mut first_frame = cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(seekable.path())
        .arg("-c")
        .arg("--from-frame")
        .arg("0")
        .arg("--to-frame")
        .arg("0")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(first_frame.len(), frame_size.try_into().unwrap());

    let mut last_frames = cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(seekable.path())
        .arg("-c")
        .arg("--from-frame")
        .arg("1")
        .arg("--to-frame")
        .arg("end")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    first_frame.append(&mut last_frames);
    assert_eq!(first_frame, fs::read(test_input()).unwrap());
}

#[test]
fn decompress_frames_separate_seek_table() {
    let frame_size = fs::metadata(test_input()).unwrap().len() / 6;
    let seekable = NamedTempFile::new().unwrap();
    let seek_table = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--frame-size")
        .arg(frame_size.to_string())
        .arg("--output-file")
        .arg(seekable.path())
        .arg("--seek-table-file")
        .arg(seek_table.path())
        .arg("--force")
        .assert()
        .success();

    let first_frame = cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(seekable.path())
        .arg("--seek-table-file")
        .arg(seek_table.path())
        .arg("-c")
        .arg("--from-frame")
        .arg("0")
        .arg("--to-frame")
        .arg("0")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(first_frame.len(), frame_size.try_into().unwrap());
    assert_eq!(
        first_frame,
        fs::read(test_input()).unwrap()[0..frame_size as usize]
    );
}

#[test]
fn decompress_frame_index_out_of_range() {
    // Let the complete file fit in one frame
    let frame_size = fs::metadata(test_input()).unwrap().len();
    let seekable = NamedTempFile::new().unwrap();
    compress_test_input(seekable.path(), &frame_size.to_string());

    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(seekable.path())
        .arg("--from-frame")
        .arg("1")
        .assert()
        .failure();

    cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(seekable.path())
        .arg("--from-frame")
        .arg("0")
        .arg("--to-frame")
        .arg("1")
        .assert()
        .failure();
}

#[test]
fn decompress_between_offset_and_offset_limit() {
    let frame_size = fs::metadata(test_input()).unwrap().len() / 9;
    let seekable = NamedTempFile::new().unwrap();
    compress_test_input(seekable.path(), &frame_size.to_string());

    let offset = frame_size + frame_size / 2;
    let offset_limit = 4 * frame_size + frame_size / 2;

    let out = cargo_bin_cmd!("zeekstd")
        .arg("decompress")
        .arg(seekable.path())
        .arg("-c")
        .arg("--from")
        .arg(offset.to_string())
        .arg("--to")
        .arg(offset_limit.to_string())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(
        out,
        fs::read(test_input()).unwrap()[offset as usize..offset_limit as usize]
    );
}

#[test]
#[allow(clippy::naive_bytecount)]
fn list_seekable() {
    let frame_size = fs::metadata(test_input()).unwrap().len() / 14;
    let seekable = NamedTempFile::new().unwrap();
    compress_test_input(seekable.path(), &frame_size.to_string());

    let out = cargo_bin_cmd!("zeekstd")
        .arg("list")
        .arg(seekable.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Expect two lines
    assert_eq!(2, out.iter().filter(|x| **x == b'\n').count());

    let out = cargo_bin_cmd!("zeekstd")
        .arg("list")
        .arg("--detail")
        .arg(seekable.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Expect 16 lines
    assert_eq!(16, out.iter().filter(|x| **x == b'\n').count());
}

#[test]
fn list_separate_seek_table() {
    let frame_size = fs::metadata(test_input()).unwrap().len() / 6;
    let seekable = NamedTempFile::new().unwrap();
    let seek_table = NamedTempFile::new().unwrap();

    cargo_bin_cmd!("zeekstd")
        .arg("compress")
        .arg(test_input())
        .arg("--frame-size")
        .arg(frame_size.to_string())
        .arg("--output-file")
        .arg(seekable.path())
        .arg("--seek-table-file")
        .arg(seek_table.path())
        .arg("--force")
        .assert()
        .success();

    cargo_bin_cmd!("zeekstd")
        .arg("list")
        .arg(seek_table.path())
        .arg("--seek-table-format")
        .arg("head")
        .assert()
        .success();
}
