#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_dir"
exec make all "$@"
