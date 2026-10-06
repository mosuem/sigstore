// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;

import 'package:boring/boring.dart' as bssl;

import 'bindings/lib.g.dart';

bool _boringInitialized = false;

/// Ensures `package:boring` (`libbssl_dart`) function pointers have been
/// registered with the underlying `sigstore_ffi` Rust library in the current
/// isolate.
void ensureBoringInitialized() {
  if (_boringInitialized) return;
  _retainBoringSymbolsForRecordUse();
  SigstoreClient.initBoring(_boringSymbolAddresses());
  _boringInitialized = true;
}

/// Retains the 28 verification and digest functions from `package:boring` for
/// AOT link-hook tree-shaking (`@RecordUse()`).
///
/// 1. All 28 functions are required at runtime because `sigstore-verify` and
///    `sigstore-tuf` dispatch algorithms dynamically based on the certificates
///    and keys in the runtime bundle or TUF metadata.
/// 2. Dart's `Native.addressOf` is not tracked as a `@RecordUse()`, and
///    `package:boring` (`0.4.1`) only generates `@RecordUse()`-annotated
///    `bssl.addresses.*` getters for `*_free` and `*_cleanup` functions. Once
///    `package:boring` exposes `bssl.addresses.*` for all functions, this
///    helper can be removed in favor of `bssl.addresses.<fn>.address`.
@pragma('vm:never-inline')
void _retainBoringSymbolsForRecordUse() {
  bssl.ERR_clear_error();
  if (DateTime.now().millisecondsSinceEpoch == 0) {
    final p = ffi.nullptr;
    bssl.EVP_sha256();
    bssl.EVP_sha384();
    bssl.EVP_sha512();
    bssl.EVP_MD_CTX_new();
    bssl.EVP_MD_CTX_free(p.cast());
    bssl.EVP_MD_CTX_copy_ex(p.cast(), p.cast());
    bssl.EVP_DigestInit_ex(p.cast(), p.cast(), p.cast());
    bssl.EVP_DigestUpdate(p.cast(), p.cast(), 0);
    bssl.EVP_DigestFinal_ex(p.cast(), p.cast(), p.cast());
    bssl.EVP_DigestVerifyInit(p.cast(), p.cast(), p.cast(), p.cast(), p.cast());
    bssl.EVP_DigestVerify(p.cast(), p.cast(), 0, p.cast(), 0);
    bssl.EVP_PKEY_free(p.cast());
    bssl.EVP_PKEY_bits(p.cast());
    bssl.EVP_PKEY_CTX_new(p.cast(), p.cast());
    bssl.EVP_PKEY_CTX_free(p.cast());
    bssl.EVP_PKEY_verify_init(p.cast());
    bssl.EVP_PKEY_verify(p.cast(), p.cast(), 0, p.cast(), 0);
    bssl.EVP_PKEY_CTX_set_rsa_padding(p.cast(), 0);
    bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(p.cast(), 0);
    bssl.EVP_PKEY_CTX_set_signature_md(p.cast(), p.cast());
    bssl.EVP_pkey_ec_p256();
    bssl.EVP_pkey_ec_p384();
    bssl.EVP_pkey_ec_p521();
    bssl.EVP_pkey_ed25519();
    bssl.EVP_pkey_rsa();
    bssl.EVP_PKEY_from_raw_public_key(p.cast(), p.cast(), 0);
    bssl.EVP_PKEY_from_subject_public_key_info(p.cast(), 0, p.cast(), 0);
  }
}

List<int> _boringSymbolAddresses() => <int>[
  ffi.Native.addressOf<ffi.NativeFunction<ffi.Void Function()>>(
    bssl.ERR_clear_error,
  ).address,
  ffi.Native.addressOf<ffi.NativeFunction<ffi.Pointer<bssl.EVP_MD> Function()>>(
    bssl.EVP_sha256,
  ).address,
  ffi.Native.addressOf<ffi.NativeFunction<ffi.Pointer<bssl.EVP_MD> Function()>>(
    bssl.EVP_sha384,
  ).address,
  ffi.Native.addressOf<ffi.NativeFunction<ffi.Pointer<bssl.EVP_MD> Function()>>(
    bssl.EVP_sha512,
  ).address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Pointer<bssl.EVP_MD_CTX> Function()>
      >(bssl.EVP_MD_CTX_new)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_MD_CTX>)>
      >(bssl.EVP_MD_CTX_free)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_MD_CTX>,
            ffi.Pointer<bssl.EVP_MD_CTX>,
          )
        >
      >(bssl.EVP_MD_CTX_copy_ex)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_MD_CTX>,
            ffi.Pointer<bssl.EVP_MD>,
            ffi.Pointer<bssl.ENGINE>,
          )
        >
      >(bssl.EVP_DigestInit_ex)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_MD_CTX>,
            ffi.Pointer<ffi.Void>,
            ffi.Size,
          )
        >
      >(bssl.EVP_DigestUpdate)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_MD_CTX>,
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.UnsignedInt>,
          )
        >
      >(bssl.EVP_DigestFinal_ex)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_MD_CTX>,
            ffi.Pointer<ffi.Pointer<bssl.EVP_PKEY_CTX>>,
            ffi.Pointer<bssl.EVP_MD>,
            ffi.Pointer<bssl.ENGINE>,
            ffi.Pointer<bssl.EVP_PKEY>,
          )
        >
      >(bssl.EVP_DigestVerifyInit)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_MD_CTX>,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
          )
        >
      >(bssl.EVP_DigestVerify)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_PKEY>)>
      >(bssl.EVP_PKEY_free)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Int Function(ffi.Pointer<bssl.EVP_PKEY>)>
      >(bssl.EVP_PKEY_bits)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Pointer<bssl.EVP_PKEY_CTX> Function(
            ffi.Pointer<bssl.EVP_PKEY>,
            ffi.Pointer<bssl.ENGINE>,
          )
        >
      >(bssl.EVP_PKEY_CTX_new)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_PKEY_CTX>)>
      >(bssl.EVP_PKEY_CTX_free)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Int Function(ffi.Pointer<bssl.EVP_PKEY_CTX>)>
      >(bssl.EVP_PKEY_verify_init)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_PKEY_CTX>,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
          )
        >
      >(bssl.EVP_PKEY_verify)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(ffi.Pointer<bssl.EVP_PKEY_CTX>, ffi.Int)
        >
      >(bssl.EVP_PKEY_CTX_set_rsa_padding)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(ffi.Pointer<bssl.EVP_PKEY_CTX>, ffi.Int)
        >
      >(bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Int Function(
            ffi.Pointer<bssl.EVP_PKEY_CTX>,
            ffi.Pointer<bssl.EVP_MD>,
          )
        >
      >(bssl.EVP_PKEY_CTX_set_signature_md)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Pointer<bssl.EVP_PKEY_ALG> Function()>
      >(bssl.EVP_pkey_ec_p256)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Pointer<bssl.EVP_PKEY_ALG> Function()>
      >(bssl.EVP_pkey_ec_p384)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Pointer<bssl.EVP_PKEY_ALG> Function()>
      >(bssl.EVP_pkey_ec_p521)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Pointer<bssl.EVP_PKEY_ALG> Function()>
      >(bssl.EVP_pkey_ed25519)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<ffi.Pointer<bssl.EVP_PKEY_ALG> Function()>
      >(bssl.EVP_pkey_rsa)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Pointer<bssl.EVP_PKEY> Function(
            ffi.Pointer<bssl.EVP_PKEY_ALG>,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
          )
        >
      >(bssl.EVP_PKEY_from_raw_public_key)
      .address,
  ffi.Native.addressOf<
        ffi.NativeFunction<
          ffi.Pointer<bssl.EVP_PKEY> Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Pointer<bssl.EVP_PKEY_ALG>>,
            ffi.Size,
          )
        >
      >(bssl.EVP_PKEY_from_subject_public_key_info)
      .address,
];
