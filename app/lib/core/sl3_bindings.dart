// Raw Dart FFI bindings for the libsl3 C ABI (Go `-buildmode=c-shared`).
//
//   char* SL3Version(void);
//   char* SL3ParseLink(char* link);
//   char* SL3Start(char* configJSON);
//   char* SL3Stop(void);
//   char* SL3Status(void);
//   char* SL3Probe(char* url, int timeoutMs);
//   void  SL3Free(char* p);
//
// Every char* returned is heap-allocated UTF-8 JSON owned by the core and must
// be released with SL3Free. Several calls block, so use these bindings from a
// background isolate (see sl3_service.dart), never directly from the UI.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

typedef _NoArgC = Pointer<Utf8> Function();
typedef _StrArgC = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _ProbeC = Pointer<Utf8> Function(Pointer<Utf8>, Int32);
typedef _ProbeDart = Pointer<Utf8> Function(Pointer<Utf8>, int);
typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

class Sl3Bindings {
  /// Throws [ArgumentError] if any of the expected symbols is missing.
  Sl3Bindings(DynamicLibrary lib)
    : _version = lib.lookupFunction<_NoArgC, _NoArgC>('SL3Version'),
      _parseLink = lib.lookupFunction<_StrArgC, _StrArgC>('SL3ParseLink'),
      _start = lib.lookupFunction<_StrArgC, _StrArgC>('SL3Start'),
      _stop = lib.lookupFunction<_NoArgC, _NoArgC>('SL3Stop'),
      _status = lib.lookupFunction<_NoArgC, _NoArgC>('SL3Status'),
      _probe = lib.lookupFunction<_ProbeC, _ProbeDart>('SL3Probe'),
      _free = lib.lookupFunction<_FreeC, _FreeDart>('SL3Free');

  /// Opens [path] (dlopen caches it, so re-opening per isolate is cheap).
  factory Sl3Bindings.open(String path) =>
      Sl3Bindings(DynamicLibrary.open(path));

  final Pointer<Utf8> Function() _version;
  final Pointer<Utf8> Function(Pointer<Utf8>) _parseLink;
  final Pointer<Utf8> Function(Pointer<Utf8>) _start;
  final Pointer<Utf8> Function() _stop;
  final Pointer<Utf8> Function() _status;
  final Pointer<Utf8> Function(Pointer<Utf8>, int) _probe;
  final void Function(Pointer<Utf8>) _free;

  String version() => _take(_version());
  String status() => _take(_status());
  String stop() => _take(_stop());
  String parseLink(String link) => _withArg(link, _parseLink);
  String start(String configJson) => _withArg(configJson, _start);

  String probe(String url, int timeoutMs) {
    final arg = url.toNativeUtf8();
    try {
      return _take(_probe(arg, timeoutMs));
    } finally {
      malloc.free(arg);
    }
  }

  String _withArg(String s, Pointer<Utf8> Function(Pointer<Utf8>) fn) {
    final arg = s.toNativeUtf8();
    try {
      return _take(fn(arg));
    } finally {
      malloc.free(arg);
    }
  }

  /// Copies the core-owned string into Dart and frees it with SL3Free.
  String _take(Pointer<Utf8> p) {
    if (p == nullptr) return '{"ok":false,"error":"core returned NULL"}';
    try {
      return p.toDartString();
    } finally {
      _free(p);
    }
  }
}

/// Outcome of searching for and opening libsl3.
class Sl3LibLocation {
  const Sl3LibLocation({
    required this.path,
    required this.searched,
    required this.errors,
  });

  /// Path that opened successfully, or null if none did.
  final String? path;

  /// Every candidate path tried, in order.
  final List<String> searched;

  /// dlopen / symbol errors for candidates that existed but failed to load.
  final List<String> errors;

  bool get found => path != null;

  /// The canonical place the packaged app expects the library.
  String get expectedPath => searched.isEmpty ? libFileName : searched.first;
}

String get libFileName {
  if (Platform.isMacOS || Platform.isIOS) return 'libsl3.dylib';
  if (Platform.isWindows) return 'sl3.dll';
  return 'libsl3.so';
}

/// Candidate locations, in priority order:
/// 1. the app bundle: `<App>.app/Contents/Frameworks/libsl3.dylib`
/// 2. the `SL3_LIB` environment variable (full path to the library)
/// 3. dev fallbacks: `../core/build/libsl3.dylib` relative to the working
///    directory, and `core/build/libsl3.dylib` under any ancestor of the
///    executable (finds `singlink-protocol-3/core/build` from the build tree).
List<String> sl3LibCandidates({
  String? executable,
  Map<String, String>? environment,
  String? workingDirectory,
}) {
  final sep = Platform.pathSeparator;
  final exe = File(executable ?? Platform.resolvedExecutable).absolute;
  final env = environment ?? Platform.environment;
  final cwd = workingDirectory ?? Directory.current.path;
  final name = libFileName;
  final out = <String>[];

  void add(String p) {
    final norm = File(p).absolute.uri.normalizePath().toFilePath();
    if (!out.contains(norm)) out.add(norm);
  }

  // .../X.app/Contents/MacOS/exe -> .../X.app/Contents/Frameworks/libsl3.dylib
  if (Platform.isMacOS) {
    add('${exe.parent.parent.path}${sep}Frameworks$sep$name');
  } else {
    add('${exe.parent.path}$sep$name');
  }

  final fromEnv = env['SL3_LIB'];
  if (fromEnv != null && fromEnv.trim().isNotEmpty) add(fromEnv.trim());

  add('$cwd$sep..${sep}core${sep}build$sep$name');

  var dir = exe.parent;
  for (var i = 0; i < 12; i++) {
    add('${dir.path}${sep}core${sep}build$sep$name');
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
  return out;
}

/// Tries each candidate until one opens and exposes all SL3 symbols.
/// Never throws.
Sl3LibLocation locateSl3Lib({List<String>? candidates}) {
  final searched = candidates ?? sl3LibCandidates();
  final errors = <String>[];
  for (final p in searched) {
    if (!File(p).existsSync()) continue;
    try {
      Sl3Bindings.open(p);
      return Sl3LibLocation(path: p, searched: searched, errors: errors);
    } catch (e) {
      errors.add('$p: $e');
    }
  }
  return Sl3LibLocation(path: null, searched: searched, errors: errors);
}
