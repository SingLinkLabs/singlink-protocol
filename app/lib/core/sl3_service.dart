// High-level async wrapper over libsl3.
//
// Every core call runs in a short-lived background isolate (Isolate.run) that
// re-opens the DynamicLibrary by path, so blocking calls such as SL3Start or
// SL3Probe never freeze the UI. The Go runtime is process-wide, so state set by
// SL3Start in one isolate is visible to SL3Status in another.

import 'dart:convert';
import 'dart:isolate';

import '../models/core_status.dart';
import '../models/profile.dart';
import 'sl3_bindings.dart';

/// Thrown when a call is made while the core library is not loaded.
class Sl3UnavailableException implements Exception {
  const Sl3UnavailableException();
  @override
  String toString() => '協議核心未載入';
}

class Sl3Service {
  Sl3Service._(this.location);

  /// Searches for libsl3 and verifies it exposes the full ABI. Never throws:
  /// check [available] / [location] to show a banner instead of crashing.
  factory Sl3Service.locate() => Sl3Service._(locateSl3Lib());

  /// Binds to a specific library file (tests, custom launchers).
  factory Sl3Service.at(String path) =>
      Sl3Service._(locateSl3Lib(candidates: [path]));

  /// For tests / previews: a service with no core.
  factory Sl3Service.unavailable({List<String> searched = const []}) =>
      Sl3Service._(
        Sl3LibLocation(path: null, searched: searched, errors: const []),
      );

  final Sl3LibLocation location;

  bool get available => location.found;

  Future<CoreVersion> version() async =>
      CoreVersion.fromJson(await _json((b) => b.version()));

  Future<ParseLinkResult> parseLink(String link) async {
    final trimmed = link.trim();
    if (trimmed.isEmpty) return ParseLinkResult.failure('連結為空');
    try {
      final json = await _json((b) => b.parseLink(trimmed));
      return ParseLinkResult.fromJson(trimmed, json);
    } on Sl3UnavailableException catch (e) {
      return ParseLinkResult.failure(e.toString());
    }
  }

  Future<OpResult> start({required String link, required String listen}) =>
      _op(() {
        final cfg = jsonEncode({'link': link, 'listen': listen});
        return _json((b) => b.start(cfg));
      });

  Future<OpResult> stop() => _op(() => _json((b) => b.stop()));

  Future<CoreStatus> status() async =>
      CoreStatus.fromJson(await _json((b) => b.status()));

  Future<ProbeResult> probe(String url, {int timeoutMs = 8000}) async {
    try {
      return ProbeResult.fromJson(await _json((b) => b.probe(url, timeoutMs)));
    } catch (e) {
      return ProbeResult(ok: false, error: e.toString());
    }
  }

  Future<OpResult> _op(Future<Map<String, dynamic>> Function() call) async {
    try {
      return OpResult.fromJson(await call());
    } catch (e) {
      return OpResult(false, e.toString());
    }
  }

  Future<Map<String, dynamic>> _json(
    String Function(Sl3Bindings b) call,
  ) async {
    final path = location.path;
    if (path == null) throw const Sl3UnavailableException();
    final raw = await _runInIsolate(path, call);
    return decodeCoreJson(raw);
  }
}

/// Top-level so the isolate closure captures only [path] and [call]
/// (both sendable), never a Sl3Service instance.
Future<String> _runInIsolate(
  String path,
  String Function(Sl3Bindings b) call,
) => Isolate.run(() => call(Sl3Bindings.open(path)));

/// Decodes a core reply; malformed output becomes an `{"ok":false}` object.
Map<String, dynamic> decodeCoreJson(String raw) {
  try {
    final v = jsonDecode(raw);
    if (v is Map<String, dynamic>) return v;
    return {'ok': false, 'error': '核心回傳格式錯誤：$raw'};
  } on FormatException {
    return {'ok': false, 'error': '核心回傳非 JSON：$raw'};
  }
}
