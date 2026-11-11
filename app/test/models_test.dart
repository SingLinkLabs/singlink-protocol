import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sl3_client/core/app_store.dart';
import 'package:sl3_client/core/client_controller.dart';
import 'package:sl3_client/core/sl3_bindings.dart';
import 'package:sl3_client/core/sl3_service.dart';
import 'package:sl3_client/models/core_status.dart';
import 'package:sl3_client/models/profile.dart';
import 'package:sl3_client/ui/format.dart';

const link = 'sl3://example-token@hk1.example.com:443?name=HK%201';

Map<String, dynamic> okReply() => decodeCoreJson('''
{"ok":true,"profile":{"name":"HK 1","server":"hk1.example.com:443",
 "transport":"tls","sni":"cdn.example.com","subject":"a1b2c3","plan":2,
 "expiresAt":1893456000,"caps":["tcp","udp"]}}''');

void main() {
  group('SL3ParseLink reply', () {
    test('ok reply becomes a Profile', () {
      final r = ParseLinkResult.fromJson('  $link ', okReply());
      expect(r.ok, isTrue);
      final p = r.profile!;
      expect(p.link, link);
      expect(p.name, 'HK 1');
      expect(p.server, 'hk1.example.com:443');
      expect(p.transport, 'tls');
      expect(p.sni, 'cdn.example.com');
      expect(p.subject, 'a1b2c3');
      expect(p.plan, 2);
      expect(p.expiresAt, DateTime.fromMillisecondsSinceEpoch(1893456000000));
      expect(p.isExpired, isFalse);
      expect(p.caps, ['tcp', 'udp']);
    });

    test('error reply', () {
      final r = ParseLinkResult.fromJson(
        link,
        decodeCoreJson('{"ok":false,"error":"bad signature"}'),
      );
      expect(r.ok, isFalse);
      expect(r.error, 'bad signature');
    });

    test('ok:true without profile is treated as failure', () {
      final r = ParseLinkResult.fromJson(link, {'ok': true});
      expect(r.ok, isFalse);
      expect(r.error, isNotEmpty);
    });

    test('tolerates missing / odd fields', () {
      final p = Profile.fromCore(link, {
        'server': 'h:1',
        'plan': '3',
        'expiresAt': 0,
        'caps': null,
      });
      expect(p.displayName, 'h:1');
      expect(p.plan, 3);
      expect(p.expiresAt, isNull);
      expect(p.isExpired, isFalse);
      expect(p.caps, isEmpty);
    });

    test('expired profile', () {
      final p = Profile.fromCore(link, {'server': 'h:1', 'expiresAt': 1000});
      expect(p.isExpired, isTrue);
    });

    test('non-JSON core output is wrapped as an error', () {
      expect(decodeCoreJson('panic: boom')['ok'], isFalse);
      expect(decodeCoreJson('[1,2]')['ok'], isFalse);
    });
  });

  test('Profile persistence round-trip', () {
    final p = ParseLinkResult.fromJson(link, okReply()).profile!;
    final back = Profile.fromJson(
      jsonDecode(jsonEncode(p.toJson())) as Map<String, dynamic>,
    );
    expect(back.toJson(), p.toJson());
    expect(back.id, p.id);
  });

  test('AppStore save/load', () async {
    final dir = await Directory.systemTemp.createTemp('sl3_store_test');
    addTearDown(() => dir.delete(recursive: true));
    final store = AppStore(File('${dir.path}/sub/state.json'));
    expect((await store.load()).profiles, isEmpty);

    final p = ParseLinkResult.fromJson(link, okReply()).profile!;
    await store.save(
      AppState(profiles: [p], selectedId: p.id, listen: '127.0.0.1:7890'),
    );
    final s = await store.load();
    expect(s.profiles.single.server, 'hk1.example.com:443');
    expect(s.selectedId, p.id);
    expect(s.listen, '127.0.0.1:7890');

    await store.file.writeAsString('{corrupt');
    expect((await store.load()).listen, defaultListen);
  });

  test('status / probe / op replies', () {
    final s = CoreStatus.fromJson(
      decodeCoreJson(
        '{"running":true,"listen":"127.0.0.1:1080","up":1024,"down":2048,'
        '"conns":3,"since":1700000000,"lastError":""}',
      ),
    );
    expect(s.running, isTrue);
    expect(s.up, 1024);
    expect(s.down, 2048);
    expect(s.conns, 3);
    expect(s.since, DateTime.fromMillisecondsSinceEpoch(1700000000000));

    final ok = ProbeResult.fromJson({
      'ok': true,
      'status': 204,
      'latencyMs': 87,
    });
    expect([ok.ok, ok.status, ok.latencyMs], [true, 204, 87]);
    final bad = ProbeResult.fromJson({'ok': false, 'error': 'timeout'});
    expect([bad.ok, bad.error], [false, 'timeout']);

    expect(OpResult.fromJson({'ok': true}).ok, isTrue);
    expect(OpResult.fromJson({'ok': false, 'error': 'x'}).error, 'x');
    expect(
      CoreVersion.fromJson({
        'version': '3.0.0-draft',
        'protocol': 'SL3/1',
      }).toString(),
      '3.0.0-draft · SL3/1',
    );
  });

  test('service without core fails gracefully', () async {
    final svc = Sl3Service.unavailable();
    expect(svc.available, isFalse);
    final r = await svc.parseLink(link);
    expect(r.ok, isFalse);
    expect((await svc.start(link: link, listen: defaultListen)).ok, isFalse);
  });

  test('library candidates: bundle first, then SL3_LIB, then dev paths', () {
    final c = sl3LibCandidates(
      executable:
          '/x/proj/app/build/Debug/sl3_client.app/Contents/MacOS/sl3_client',
      environment: {'SL3_LIB': '/opt/libsl3.dylib'},
      workingDirectory: '/x/proj/app',
    );
    if (Platform.isMacOS) {
      expect(
        c[0],
        '/x/proj/app/build/Debug/sl3_client.app/Contents/Frameworks/libsl3.dylib',
      );
      expect(c[1], '/opt/libsl3.dylib');
      expect(c[2], '/x/proj/core/build/libsl3.dylib');
      expect(c.toSet().length, c.length);
    }
    final loc = locateSl3Lib(candidates: ['/nonexistent/libsl3.dylib']);
    expect(loc.found, isFalse);
    expect(loc.expectedPath, '/nonexistent/libsl3.dylib');
  });

  test('validateListen', () {
    expect(validateListen('127.0.0.1:1080'), isNull);
    expect(validateListen('[::1]:1080'), isNull);
    expect(validateListen('127.0.0.1'), isNotNull);
    expect(validateListen('127.0.0.1:0'), isNotNull);
    expect(validateListen('127.0.0.1:70000'), isNotNull);
    expect(validateListen(':1080'), isNotNull);
  });

  test('formatting', () {
    expect(formatBytes(0), '0 B');
    expect(formatBytes(1536), '1.50 KB');
    expect(formatBytes(15 * 1024 * 1024), '15.0 MB');
    expect(formatRate(2048), '2.00 KB/s');
    expect(formatDuration(const Duration(seconds: 65)), '01:05');
    expect(
      formatDuration(const Duration(hours: 1, minutes: 2, seconds: 3)),
      '1:02:03',
    );
    expect(transportLabel('tls'), 'TLS');
  });
}
