// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:io';

void main() async {
  print('Generating Dart bindings from Rust bridge via Diplomat...');

  final packageRoot = Platform.script.resolve('../');
  final diplomatCargo = packageRoot.resolve('../diplomat/Cargo.toml');
  final rustLib = packageRoot.resolve('rust/src/lib.rs');
  final outBindings = packageRoot.resolve('lib/src/bindings/');

  final process = await Process.run(
    'cargo',
    [
      'run',
      '--manifest-path',
      diplomatCargo.toFilePath(),
      '-p',
      'diplomat-tool',
      '--',
      'dart',
      outBindings.toFilePath(),
      '-e',
      rustLib.toFilePath(),
    ],
    workingDirectory: packageRoot.toFilePath(),
  );

  print(process.stdout);
  if (process.stderr.toString().isNotEmpty) {
    print(process.stderr);
  }

  if (process.exitCode != 0) {
    exit(process.exitCode);
  }

  print('Dart bindings generated successfully.');
}
