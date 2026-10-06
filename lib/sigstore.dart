/// A Dart client library for Sigstore cryptographic bundle inspection and
/// artifact verification, backed by `sigstore-rust` and `package:boring`.
library;

export 'src/bindings/lib.g.dart';
export 'src/boring_init.dart' show ensureBoringInitialized;
export 'src/tuf_refresh.dart' show SigstoreClientTuf;
