#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# Public-only SSH bootstrap. All options and defaults are owned by the product.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ ! -x "$repo_dir/unmoor" ]; then
    printf '%s\n' 'unmoor: binary missing; run bin/build.sh on this machine first' >&2
    exit 1
fi
exec "$repo_dir/tools/unmoor-deaddrop-ssh" --local "$repo_dir/unmoor" "$@"
