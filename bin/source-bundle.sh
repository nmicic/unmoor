#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# Export only committed source, never ignored private data or build products.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_dir"
if [ ! -d .git ]; then
    printf '%s\n' 'bundle: run in the standalone Git checkout, not an extracted archive' >&2
    exit 1
fi
tree_status=$(git status --porcelain --untracked-files=all)
if [ -n "$tree_status" ]; then
    printf '%s\n' 'bundle: commit intended source changes first; checkout is not clean' >&2
    exit 1
fi
revision=$(git rev-parse --short=12 HEAD)
mkdir -p dist
archive="dist/unmoor-$revision.tar.gz"
if [ -e "$archive" ]; then
    printf '%s\n' "bundle: already exists: $repo_dir/$archive" >&2
    exit 1
fi
git archive --format=tar.gz --prefix=unmoor/ -o "$archive" HEAD
printf '%s\n' "$repo_dir/$archive"
