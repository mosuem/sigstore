// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:io';
import 'dart:typed_data';

import 'bindings/lib.g.dart';
import 'boring_init.dart';

/// Extension on [SigstoreClient] driving the Rust `sigstore-tuf` verification
/// state machine over Dart's [HttpClient].
extension SigstoreClientTuf on SigstoreClient {
  /// Refreshes the TUF trusted root from the Sigstore TUF mirror into
  /// [cacheDir] using full TUF verification (`sigstore-tuf`).
  ///
  /// - [tufMirrorUrl]: URL of the Sigstore TUF repository mirror
  ///   (e.g. `https://tuf-repo-cdn.sigstore.dev`).
  /// - [cacheDir]: Local filesystem directory path to cache downloaded TUF
  ///   metadata and targets.
  /// - [httpClient]: Optional custom [HttpClient] for fetching TUF metadata
  ///   and target files. If omitted, a temporary [HttpClient] is created and
  ///   closed when the refresh finishes.
  ///
  /// Returns the verified `trusted_root.json` string.
  ///
  /// Throws [SigstoreError] if network retrieval or TUF cryptographic
  /// verification fails.
  Future<String> refreshTrustedRoot(
    String tufMirrorUrl,
    String cacheDir, {
    HttpClient? httpClient,
  }) async {
    ensureBoringInitialized();
    final updater = SigstoreTufUpdater.create(tufMirrorUrl, cacheDir);
    final client =
        httpClient ??
        (HttpClient()..connectionTimeout = const Duration(seconds: 30));
    final ownsClient = httpClient == null;
    try {
      while (true) {
        final pendingUrl = updater.poll();
        if (pendingUrl.isEmpty) {
          return updater.takeResult();
        }
        final maxBytes = updater.maxResponseBytes();
        try {
          final uri = Uri.parse(pendingUrl);
          final request = await client.getUrl(uri);
          final response = await request.close();
          if (response.contentLength > maxBytes) {
            updater.provideError(
              'Response content-length ${response.contentLength} '
              'exceeds max $maxBytes',
            );
            continue;
          }
          final builder = BytesBuilder(copy: false);
          var exceeded = false;
          await for (final chunk in response) {
            if (builder.length + chunk.length > maxBytes) {
              exceeded = true;
              break;
            }
            builder.add(chunk);
          }
          if (exceeded) {
            updater.provideError('Response body exceeds max $maxBytes bytes');
            continue;
          }
          updater.provideResponse(response.statusCode, builder.takeBytes());
        } on Object catch (e) {
          updater.provideError(e.toString());
        }
      }
    } finally {
      if (ownsClient) {
        client.close(force: true);
      }
    }
  }
}
