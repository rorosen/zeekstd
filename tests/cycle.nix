{
  zeekstd,
  zstd,
  runCommand,
}:
runCommand "zeekstd-cycle-test"
  {
    nativeBuildInputs = [
      zeekstd
      zstd
    ];
  }
  ''
    set -x

    seq 28000 > num

    # Compress via input file and stdin
    zeekstd num
    cat num | zeekstd -o num.stdin.zst
    zeekstd -c num > num.stdout.zst

    # Compressions yield the same result
    cmp num.zst num.stdin.zst
    cmp num.zst num.stdout.zst

    # Decompress with zeekstd and zstd
    zeekstd d num.zst -o num.decomp
    zeekstd d num.stdout.zst -c > num.stdout.decomp
    zstd -d num.zst -o num.zstd.decomp

    # Decompressions restore the original
    cmp num num.decomp
    cmp num num.stdout.decomp
    cmp num num.zstd.decomp

    # Cycle with separate seek table
    cat num | zeekstd -o num-frames.zst --seek-table-file st.bin
    zeekstd d num-frames.zst --seek-table-file st.bin -o num-frames.decomp
    cmp num num-frames.decomp

    # Cycle without seek table and regular zstd decoder
    zeekstd -o num-frames-nost.zst --seek-table-file /dev/null num
    zstd -d num-frames-nost.zst -o num-frames-nost.decomp
    cmp num num-frames-nost.decomp

    touch $out
  ''
