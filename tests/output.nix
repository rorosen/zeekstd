{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-output-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 30000 > num

  # Derive out name from input
  zeekstd num
  ls num.zst

  # Out file exists, force overwrite works
  zeekstd num && exit 1
  zeekstd num --force

  # Out file exists, force overwrite works
  cat num | zeekstd -o num.zst && exit 1
  cat num | zeekstd -o num.zst --force

  # Succeed with other out file
  cat num | zeekstd -o num2.zst
  ls num2.zst

  # Refuse writing to terminal
  cat num | zeekstd -c && exit 1
  # Works with redirect stdout
  cat num | zeekstd -c > num3.zst
  # Works if forced
  cat num | zeekstd -cf

  # All created files are equal
  cmp num.zst num2.zst
  cmp num.zst num3.zst

  # Out file isn't created if in file doesn't exist
  zeekstd foo.txt -o bar.zst && exit 1
  ls bar.zst && exit 1

  # Can always write to /dev/null
  cat num | zeekstd -o /dev/null --seek-table-file st.bin
  ls st.bin
  # Seek table file gets also not overwritten
  cat num | zeekstd -o /dev/null --seek-table-file st.bin && exit 1

  touch $out
''
