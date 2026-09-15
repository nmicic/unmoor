<!-- Copyright (c) The mlkem-native project authors -->
<!-- SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT -->

# Unmoor mlkem-native provenance

- Upstream: `https://github.com/pq-code-package/mlkem-native`
- Release: `v1.1.0`
- Commit: `d2cae2be522a67bfae26100fdb520576f1b2ef90`
- Release archive SHA-256:
  `79bf96b6d2d9a9d38d6aea420fc056b744898235d05e23ca0b7ce90edc922362`
- Imported: 2026-09-07

This directory contains the upstream license/relicense files and only the
portable single-compilation-unit source needed for ML-KEM-1024. Native and
assembly backends are intentionally absent. Upstream files below are copied
byte-for-byte; `unmoor_mlkem_config.h` and the project wrapper outside this
directory are Unmoor integration files.

Imported paths are `mlkem/mlkem_native.{c,h}`, all non-native files directly
under `mlkem/src/`, and the six portable files directly under
`mlkem/src/fips202/`.
