{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-list-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 20000 | zeekstd -o num.zst

  # Just check that list works, no proper test yet
  zeekstd l num.zst
  zeekstd l num.zst --from start --to end

  touch $out
''
