// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:io';

const targets = [
  'x86_64-unknown-linux-gnu',
  'aarch64-unknown-linux-gnu',
  'x86_64-apple-darwin',
  'aarch64-apple-darwin',
  'x86_64-pc-windows-msvc',
  'aarch64-linux-android',
  'x86_64-linux-android',
  'aarch64-apple-ios',
];

void main(List<String> args) async {
  final packageRoot = Platform.script.resolve('../');
  final rustDir = packageRoot.resolve('rust/');
  final outDir = Directory.fromUri(packageRoot.resolve('build/binaries/'));
  await outDir.create(recursive: true);

  print('Precompiling binaries for release...');

  for (final target in targets) {
    for (final isStatic in [false, true]) {
      final crateType = isStatic ? 'staticlib' : 'cdylib';
      final libType = isStatic ? 'static' : 'dynamic';
      print('Building target $target ($crateType)...');

      final outFile = outDir.uri.resolve('libsigstore_ffi-$libType-$target');
      final result = await Process.run(
        'cargo',
        [
          'rustc',
          '--crate-type=$crateType',
          '--release',
          '--target=$target',
          '--',
          '--emit',
          'link=${outFile.toFilePath(windows: Platform.isWindows)}',
        ],
        workingDirectory: rustDir.toFilePath(),
      );

      if (result.exitCode != 0) {
        print(
          'Warning: Build for $target failed '
          '(target toolchain might not be installed): ${result.stderr}',
        );
      } else {
        print('Successfully precompiled $outFile');
      }
    }
  }
}
