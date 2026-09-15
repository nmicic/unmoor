#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Checks that a built binary contains no development scaffolding. The patterns
# below describe classes of name, not a list of known offenders: a product
# build should never carry a symbol whose name marks it as test, fixture, mock,
# harness or chaos code, nor a string that only a test harness would look for.
set -eu
binary=${1:-./unmoor}
[ -f "$binary" ] && [ -x "$binary" ] || {
    printf '%s\n' "hygiene: missing executable: $binary" >&2
    exit 1
}

# Underscore-delimited words, so genuine product names that merely end in
# "test" (bulk_bitmap_test tests a bit) are not swept up, while test_foo,
# foo_test_bar, chaos_*, *_fixture and friends are.
symbol_classes='(^|_)(chaos|fixture|mock|harness|testonly)(_|$)|(^|_)tests?_'
string_classes='UNMOOR_[A-Z0-9_]*(TEST|FIXTURE|CHAOS|MOCK|HARNESS|RUNTIME_DIR)|[a-z0-9-]+-runtime:'

names=$(mktemp "${TMPDIR:-/tmp}/unmoor-symbols.XXXXXX")
strings_file=
trap 'rm -f "$names" "$strings_file"' EXIT
trap 'exit 1' HUP INT TERM
strings_file=$(mktemp "${TMPDIR:-/tmp}/unmoor-strings.XXXXXX")
# Drop the address/type columns and any Mach-O leading underscore, so one
# pattern reads the same way on ELF and Mach-O output.
nm "$binary" | awk '{ name = $NF; sub(/^_/, "", name); print name }' >"$names"
strings "$binary" >"$strings_file"
[ -s "$names" ] && [ -s "$strings_file" ] || {
    printf '%s\n' 'hygiene: no symbol/string evidence; cannot verify artifact' >&2
    exit 1
}
if grep -Ei "$symbol_classes" "$names"; then
    printf '%s\n' 'hygiene: forbidden development symbol in product' >&2
    exit 1
else
    match_status=$?
    [ "$match_status" -eq 1 ] || exit "$match_status"
fi
if grep -E "$string_classes" "$strings_file"; then
    printf '%s\n' 'hygiene: forbidden runtime fixture marker in product' >&2
    exit 1
else
    match_status=$?
    [ "$match_status" -eq 1 ] || exit "$match_status"
fi
printf '%s\n' 'production symbol/fixture hygiene: PASS (zero matches)'
