// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

// coverage:ignore-file

import 'package:code_assets/code_assets.dart'
    show CodeAsset, HookConfigCodeConfig, LinkInputCodeAssets, OS;
import 'package:hooks/hooks.dart' show link;
import 'package:logging/logging.dart' show Level, Logger;
import 'package:native_toolchain_c/native_toolchain_c.dart'
    show CLinker, LinkerOptions;
import 'package:record_use/record_use.dart' as record_use;

/// Run the linker to turn a static into a treeshaken dynamic library.
Future<void> main(List<String> args) async {
  await link(args, (input, output) async {
    print('Start linking');
    final CodeAsset staticLib;
    try {
      staticLib = input.assets.code.firstWhere(
        (asset) => asset.id == 'package:sigstore/src/bindings/lib.g.dart',
      );
    } catch (e) {
      // No static lib built, so assume a dynamic one was already bundled.
      return;
    }

    final recordedUses = input.recordedUses;
    Iterable<String>? usedSymbols;
    if (recordedUses == null) {
      print('No recorded uses found to treeshake unused symbols.');
    } else {
      usedSymbols = recordedUses.calls.keys
          .where(
            (id) =>
                id.library ==
                const record_use.Library(
                  'package:sigstore/src/bindings/lib.g.dart',
                ),
          )
          .map((id) => id.name)
          .where((methodName) => methodName.startsWith('_'))
          .expand(
            (methodName) => [
              if (methodName.startsWith('_internal_'))
                methodName.substring('_internal_'.length),
              methodName.substring(1),
            ],
          );
    }

    print('''
### Using symbols:
  ${usedSymbols?.join('\n') ?? 'Treeshaking disabled, using all symbols.'}
### End using symbols
''');

    await CLinker.library(
      name: 'sigstore_ffi',
      packageName: input.packageName,
      assetName: 'src/bindings/lib.g.dart',
      sources: [staticLib.file!.toFilePath()],
      libraries: switch (input.config.code.targetOS) {
        // On Windows, sigstore_ffi.lib is lacking /DEFAULTLIB directives to advise
        // the linker on what libraries to link against. To make up for that,
        // the libraries used have to be provided to the linker explicitly.
        OS.windows => const [
          'MSVCRT',
          'ws2_32',
          'userenv',
          'ntdll',
          'bcrypt',
          'crypt32',
          'secur32',
          'ncrypt',
        ],
        // On Android, libm (math library) is not linked by default, but math
        // functions like `expf` referenced in Rust libsigstore require libm.
        OS.android => const ['m'],
        _ => const [],
      },
      linkerOptions: LinkerOptions.treeshake(symbolsToKeep: usedSymbols),
    ).run(
      input: input,
      output: output,
      logger: Logger('')
        ..level = Level.ALL
        ..onRecord.listen((record) => print(record.message)),
    );
  });
}
