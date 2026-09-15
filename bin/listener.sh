#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# Direct listener entry point; recommended client.sh starts its peer via SSH.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ "$#" -eq 0 ]; then
    printf '%s\n' 'usage: bin/listener.sh [unmoor listen options]' \
        'Recommended: bin/client.sh starts the remote listener through SSH.' \
        'Manual PSK listeners need an already provisioned in-memory UNMOOR_KEY.' \
        'See HOWTO.md; global help: bin/unmoor.sh --help' >&2
    exit 2
fi
exec "$repo_dir/bin/unmoor.sh" listen "$@"
