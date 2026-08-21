# Sigstore Dart Client (`package:sigstore`)

A Dart client library for [Sigstore](https://www.sigstore.dev/) wrapping `sigstore-rust` (`sigstore-verify`, `sigstore-sign`, `sigstore-types`) using **[Diplomat](https://github.com/rust-diplomat/diplomat)** for FFI bindings generation and Dart **Native Assets** (`hook/build.dart`).

## Architecture & Features

- **Automated Bindings**: The Rust bridge in `rust/src/lib.rs` is annotated with `#[diplomat::bridge]`. All `@Native` FFI declarations and idiomatic Dart classes in `lib/src/bindings/` are generated via `dart run tool/generate_bindings.dart`.
- **Flexible Build Modes** (following `package:icu4x`):
  - `fetch` (default for consumers): Fetches precompiled dynamic libraries and verifies their SHA-256 hashes against `lib/src/hook_helpers/hashes.dart`.
  - `checkout`: Builds fresh native binaries from the local `rust/` source crate using `cargo`.
  - `local`: Links against an existing binary specified via `localPath`.

## Usage

```dart
import 'dart:convert';
import 'package:sigstore/sigstore.dart';

void main() {
  final client = SigstoreClient.create();
  final bundle = SigstoreBundle.fromJson(bundleJson);

  final policy = SigstoreVerificationPolicy(
    expectedIdentity: 'developer@example.com',
    expectedIssuer: 'https://accounts.google.com',
    offline: true,
  );

  final artifact = utf8.encode('my release artifact');
  final result = client.verify(artifact, bundle, policy);

  if (result.isValid()) {
    print('Verified: ${result.verifiedIdentity()}');
  }
}
```

## Development & Generation

### Generating Dart Bindings
```bash
dart run tool/generate_bindings.dart
```

### Running Tests
```bash
dart test
```

### Precompiling Binaries & Updating Hashes
```bash
dart run tool/precompile_binaries.dart
dart run tool/regenerate_hashes.dart <github-release-tag>
```
