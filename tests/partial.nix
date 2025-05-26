{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-partial-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 35000 > num
  zeekstd --frame-size 1K num -o num.zst

  # Decompress only the first frame
  zeekstd d -c --from 0 --to 0 num.zst > first
  size_first=$(stat -c %s first)
  [ $size_first -le 1024 ] || exit 1
  head -c "$size_first" num | cmp first

  # Partial decompression with separate seek table
  zeekstd --frame-size 1K num -o frames.zst --seek-table-file st.bin
  zeekstd d --from 0 --to 0 --seek-table-file st.bin frames.zst -o first_separate
  size_first_separate=$(stat -c %s first_separate)
  [ $size_first_separate -le 1024 ] || exit 1
  head -c "$size_first_separate" num | cmp first_separate

  cmp first first_separate

  touch $out
''
