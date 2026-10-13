#!/bin/sh
set -eu

CDPATH=''
export CDPATH
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
php_binary=${TEST_PHP_EXECUTABLE:-${1:-"$repo_root/sapi/cli/php"}}

if [ ! -x "$php_binary" ]; then
  echo "PHP test binary is not executable: $php_binary" >&2
  exit 2
fi

result_file=$(mktemp "${TMPDIR:-/tmp}/php-openssl-liveness.XXXXXX")
trap 'rm -f "$result_file"' EXIT HUP INT TERM

set +e
"$php_binary" -n "$repo_root/run-tests.php" \
  -q --set-timeout 10 -p "$php_binary" \
  -W "$result_file" \
  "$repo_root/ext/openssl/tests/gh10495.phpt" \
  "$repo_root/ext/openssl/tests/gh10495_liveness_modes.phpt" \
  "$repo_root/ext/openssl/tests/gh10495_liveness_error.phpt" \
  "$repo_root/ext/openssl/tests/phpt_extract_tls_records.phpt"
test_status=$?
set -e

if [ "$test_status" -ne 0 ]; then
  exit "$test_status"
fi

pass_count=$(awk '$1 == "PASSED" { count++ } END { print count + 0 }' "$result_file")
result_count=$(wc -l <"$result_file")
if [ "$pass_count" -ne 4 ] || [ "$result_count" -ne 4 ]; then
  echo "OpenSSL liveness controls did not all pass (passed $pass_count of $result_count)" >&2
  cat "$result_file" >&2
  exit 1
fi
