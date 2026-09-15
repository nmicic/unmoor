Monocypher 4.0.3 (single-file crypto library)

Source:  https://monocypher.org/download/monocypher-4.0.3.tar.gz
SHA-512: 40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965
License: BSD-2-Clause OR CC0-1.0.  The complete text of both licences is
         in monocypher-LICENCE.md next to this file, copied byte-for-byte
         from the upstream tarball.  The header of monocypher.c carries the
         SPDX identifier, the BSD text and a short CC0 dedication notice,
         but not the CC0 legal code; monocypher-LICENCE.md is the full one.
Date vendored: 2026-09-07

Files:
  monocypher.c   2988 lines
  monocypher.h    321 lines

SHA-256 of the exact bytes shipped here (computed at vendor time, and
re-verified against this tree on 2026-09-07):
  monocypher.c  57eb914fc88136119bd41655cccb8c250048bf54d470540625186f8ab16f64be
  monocypher.h  c494da712122da7ff679fdcf318a5317e84972b6c950fe9d896212947797facd

These hashes match the files extracted from monocypher-4.0.3.tar.gz src/
without any modification.

Used APIs:
  crypto_aead_lock        XChaCha20-Poly1305 encrypt
  crypto_aead_unlock      XChaCha20-Poly1305 decrypt
  crypto_blake2b_keyed    Session key, hello key and pair-id derivation
  crypto_blake2b_*        Transcript and incremental hash derivation
  crypto_x25519           Fresh-DH shared-secret derivation
  crypto_x25519_public_key  Fresh public-key derivation
  crypto_wipe             Secure zero of key material

(Unmoor has no on-disk key capsule, so nothing here calls crypto_argon2.)

Do not modify these files in place. To upgrade, replace both files from a
verified upstream tarball and update this README.
