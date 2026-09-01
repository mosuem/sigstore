# Changelog

## 0.1.3

- Add Native Assets link hook (`hook/link.dart`) with `package:record_use` and `package:native_toolchain_c` for binary tree-shaking.
- Validate artifact hex digest length in conformance test runner.
- Ensure `HttpClient` instances are cleanly closed in build hook and tool scripts.
- Add `dart_dependency_validator.yaml` to configure dependencies for native asset build hooks.
- Remove unused `logging` dependency.
- Map `SigstoreError::InternalError` explicitly in Rust bindings.

## 0.1.2

- Optimize precompiled Rust binary size using release profile size optimizations, LTO, single codegen unit, and symbol stripping.

## 0.1.1

- Expose `SigstoreClient.refreshTrustedRoot` for updating Sigstore TUF metadata and trusted root anchors.

## 0.1.0

- Initial release.
- Cryptographic artifact verification via `SigstoreVerifier`.
- Support for keyless verification with Rekor transparency log and Fulcio certificate validation.
- Support for Sigstore Bundle (v0.1, v0.2, v0.3) inspection and verification.
- Support for `local`, `checkout`, and precompiled `fetch` build modes via Dart Native Assets.
