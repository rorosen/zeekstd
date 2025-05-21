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
    # All compressions yield the same result
    cmp num.zst num.stdin.zst
    cmp num.zst num.stdout.zst
    # Decompress with zeekstd and zstd
    zeekstd d num.zst -o num.decomp
    zeekstd d num.zst -c > num.stdout.decomp
    zstd -d num.zst -o num.zstd.decomp
    # All decompressions restore the original
    cmp num num.decomp
    cmp num num.stdout.decomp
    cmp num num.zstd.decomp

    touch $out
  ''
