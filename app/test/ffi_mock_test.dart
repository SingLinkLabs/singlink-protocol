// Exercises the real FFI + isolate path against a C mock of libsl3 compiled on
// the fly. Skipped when no C compiler is available.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sl3_client/core/sl3_bindings.dart';
import 'package:sl3_client/core/sl3_service.dart';

void main() {
  late Directory tmp;
  String? libPath;

  setUpAll(() async {
    tmp = await Directory.systemTemp.createTemp('sl3_ffi_mock');
    final out = '${tmp.path}/$libFileName';
    final args = Platform.isMacOS
        ? ['-dynamiclib', '-o', out, 'test/fixtures/mock_libsl3.c']
        : ['-shared', '-fPIC', '-o', out, 'test/fixtures/mock_libsl3.c'];
    try {
      final r = await Process.run('cc', args);
      if (r.exitCode == 0) libPath = out;
    } on ProcessException {
      libPath = null;
    }
  });

  tearDownAll(() => tmp.delete(recursive: true));

  test('service round-trips every SL3 call through FFI', () async {
    if (libPath == null) {
      markTestSkipped('no C compiler');
      return;
    }
    final loc = locateSl3Lib(candidates: ['/nope/$libFileName', libPath!]);
    expect(loc.path, libPath);

    final s = Sl3Service.at(libPath!);
    expect(s.available, isTrue);
    expect((await s.version()).version, '3.0.0-mock');

    final bad = await s.parseLink('vmess://x');
    expect(bad.ok, isFalse);
    expect(bad.error, 'not an sl3 link');

    final good = await s.parseLink('sl3://h.example:443');
    expect(good.ok, isTrue);
    expect(good.profile!.server, 'h.example:443');

    expect(
      (await s.start(link: 'sl3://h', listen: '127.0.0.1:9')).error,
      'bad cfg',
    );
    expect(
      (await s.start(link: 'sl3://h', listen: '127.0.0.1:1080')).ok,
      isTrue,
    );

    final st = await s.status();
    expect(st.running, isTrue);
    expect(st.down, 20);
    // conns echoes the mock's SL3Free counter: every prior reply was freed.
    expect(st.conns, 5);

    final p = await s.probe(
      'https://www.gstatic.com/generate_204',
      timeoutMs: 8000,
    );
    expect(p.ok, isTrue);
    expect(p.latencyMs, 8000); // timeout int passed through intact

    expect((await s.stop()).ok, isTrue);
    expect((await s.status()).running, isFalse);
  });
}
