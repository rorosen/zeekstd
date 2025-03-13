use std::fs::File;

use anyhow::{anyhow, bail, Context, Result};
use indicatif::HumanBytes;
use zstd_safe::seekable::Seekable;

use crate::args::ListArgs;

pub fn list_frames(args: &ListArgs) -> Result<()> {
    let format_bytes = |n: u64| format!("{}", HumanBytes(n));
    let file = File::open(&args.input_file).context("Failed to open input file")?;
    let seekable = Seekable::try_create().context("Failed to create seekable object")?;
    let seekable = seekable.init_advanced(Box::new(file)).map_err(|c| {
        anyhow!(
            "Failed to initialize seekable object: {}",
            zstd_safe::get_error_name(c)
        )
    })?;

    let start_frame = if args.from_frame.is_some() {
        args.from_frame
    } else {
        args.from
            .as_ref()
            .map(|offset| seekable.offset_to_frame_index(offset.as_u64()))
    };

    let end_frame = if args.to_frame.is_some() {
        args.to_frame
    } else if let Some(offset) = &args.to {
        Some(seekable.offset_to_frame_index(offset.as_u64()))
    } else {
        args.num_frames.map(|num| start_frame.unwrap_or(0) + num)
    };

    if start_frame.is_none() && end_frame.is_none() {
        let frames = seekable.num_frames();
        let compressed = (0..frames).fold(0u64, |acc, n| {
            acc + seekable
                .frame_compressed_size(n)
                .expect("Frame index is never out of range") as u64
        });
        let decompressed = (0..frames).fold(0u64, |acc, n| {
            acc + seekable
                .frame_decompressed_size(n)
                .expect("Frame index is never out of range") as u64
        });
        let ratio = decompressed as f64 / compressed as f64;

        eprintln!(
            "{: <15} {: <15} {: <15} {: <15} {: <15}",
            "Frames", "Compressed", "Decompressed", "Ratio", "Filename"
        );
        eprintln!(
            "{: <15} {: <15} {: <15} {: <15.3} {: <15}",
            frames,
            format_bytes(compressed),
            format_bytes(decompressed),
            ratio,
            args.input_file
                .as_os_str()
                .to_str()
                .unwrap_or("¯\\_(ツ)_/¯")
        );
    } else {
        let map_error_code = |index, code| {
            anyhow!(
                "Failed to get data of frame {index}: {}",
                zstd_safe::get_error_name(code)
            )
        };
        let map_index_err = |index, err| anyhow!("Failed to get data of frame {index}: {err}");
        let start = start_frame.unwrap_or(0);
        let end = end_frame.unwrap_or_else(|| seekable.num_frames());

        if start > end {
            bail!("Start frame ({start}) cannot be greater than end frame ({end})");
        }

        eprintln!(
            "{: <15} {: <15} {: <15} {: <20} {: <20}",
            "Frame Index", "Compressed", "Decompressed", "Compressed Offset", "Decompressed Offset"
        );
        for n in start..end {
            eprintln!(
                "{: <15} {: <15} {: <15} {: <20} {: <20}",
                n,
                format_bytes(
                    seekable
                        .frame_compressed_size(n)
                        .map_err(|c| map_error_code(n, c))? as u64
                ),
                format_bytes(
                    seekable
                        .frame_decompressed_size(n)
                        .map_err(|c| map_error_code(n, c))? as u64
                ),
                seekable
                    .frame_compressed_offset(n)
                    .map_err(|err| map_index_err(n, err))?,
                seekable
                    .frame_decompressed_offset(n)
                    .map_err(|err| map_index_err(n, err))?,
            );
        }
    }

    Ok(())
}
