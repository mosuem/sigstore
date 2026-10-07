// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'package:boring/boring.dart' as bssl;

import 'bindings/lib.g.dart';

bool _boringInitialized = false;

/// Ensures `package:boring` (`libbssl_dart`) function pointers have been
/// registered with the underlying `sigstore_ffi` Rust library in the current
/// isolate.
void ensureBoringInitialized() {
  if (_boringInitialized) return;
  SigstoreVerifier.initBoring(_boringSymbolAddresses());
  _boringInitialized = true;
}

/// Returns the addresses of the 28 BoringSSL functions required by
/// `rust/aws-lc-rs-boring` (`BoringSymbols`).
///
/// Using `bssl.addresses.<fn>` (whose extension getters are annotated with
/// `@RecordUse()` in `package:boring`) ensures `package:boring`'s link hook
/// retains all 28 symbols when tree-shaking `libbssl_dart` in AOT builds.
List<int> _boringSymbolAddresses() => <int>[
  bssl.addresses.ERR_clear_error.address,
  bssl.addresses.EVP_sha256.address,
  bssl.addresses.EVP_sha384.address,
  bssl.addresses.EVP_sha512.address,
  bssl.addresses.EVP_MD_CTX_new.address,
  bssl.addresses.EVP_MD_CTX_free.address,
  bssl.addresses.EVP_MD_CTX_copy_ex.address,
  bssl.addresses.EVP_DigestInit_ex.address,
  bssl.addresses.EVP_DigestUpdate.address,
  bssl.addresses.EVP_DigestFinal_ex.address,
  bssl.addresses.EVP_DigestVerifyInit.address,
  bssl.addresses.EVP_DigestVerify.address,
  bssl.addresses.EVP_PKEY_free.address,
  bssl.addresses.EVP_PKEY_bits.address,
  bssl.addresses.EVP_PKEY_CTX_new.address,
  bssl.addresses.EVP_PKEY_CTX_free.address,
  bssl.addresses.EVP_PKEY_verify_init.address,
  bssl.addresses.EVP_PKEY_verify.address,
  bssl.addresses.EVP_PKEY_CTX_set_rsa_padding.address,
  bssl.addresses.EVP_PKEY_CTX_set_rsa_pss_saltlen.address,
  bssl.addresses.EVP_PKEY_CTX_set_signature_md.address,
  bssl.addresses.EVP_pkey_ec_p256.address,
  bssl.addresses.EVP_pkey_ec_p384.address,
  bssl.addresses.EVP_pkey_ec_p521.address,
  bssl.addresses.EVP_pkey_ed25519.address,
  bssl.addresses.EVP_pkey_rsa.address,
  bssl.addresses.EVP_PKEY_from_raw_public_key.address,
  bssl.addresses.EVP_PKEY_from_subject_public_key_info.address,
];
