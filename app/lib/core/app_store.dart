// Persists profiles and settings as one JSON file.
//
// Plugin-free on purpose (shared_preferences on macOS would need CocoaPods or
// SwiftPM). Location on macOS:
//   $HOME/Library/Application Support/com.singlinklabs.sl3Client/state.json
// Inside the App Sandbox $HOME is the app container, so this resolves to
//   ~/Library/Containers/com.singlinklabs.sl3Client/Data/Library/Application Support/...

import 'dart:convert';
import 'dart:io';

import '../models/profile.dart';

const defaultListen = '127.0.0.1:1080';

class AppState {
  AppState({
    List<Profile>? profiles,
    this.selectedId,
    this.listen = defaultListen,
  }) : profiles = profiles ?? <Profile>[];

  final List<Profile> profiles;
  String? selectedId;
  String listen;

  Map<String, dynamic> toJson() => {
    'version': 1,
    'profiles': profiles.map((p) => p.toJson()).toList(),
    'selectedId': selectedId,
    'listen': listen,
  };

  factory AppState.fromJson(Map<String, dynamic> json) {
    final list = json['profiles'];
    final listen = json['listen'];
    return AppState(
      profiles: list is List
          ? list
                .whereType<Map<String, dynamic>>()
                .map(Profile.fromJson)
                .where((p) => p.link.isNotEmpty)
                .toList()
          : null,
      selectedId: json['selectedId'] as String?,
      listen: listen is String && listen.isNotEmpty ? listen : defaultListen,
    );
  }
}

class AppStore {
  AppStore(this.file);

  /// Default per-user location (see file header).
  factory AppStore.standard() {
    final home = Platform.environment['HOME'];
    final String base;
    if (Platform.isMacOS && home != null) {
      base = '$home/Library/Application Support/com.singlinklabs.sl3Client';
    } else if (home != null) {
      base = '$home/.config/sl3_client';
    } else {
      base = '${Directory.systemTemp.path}/sl3_client';
    }
    return AppStore(File('$base/state.json'));
  }

  final File file;

  Future<AppState> load() async {
    try {
      if (!await file.exists()) return AppState();
      final v = jsonDecode(await file.readAsString());
      return v is Map<String, dynamic> ? AppState.fromJson(v) : AppState();
    } catch (_) {
      // Corrupt or unreadable file: start fresh rather than fail to launch.
      return AppState();
    }
  }

  /// Atomic write (temp file + rename).
  Future<void> save(AppState state) async {
    await file.parent.create(recursive: true);
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsString(
      const JsonEncoder.withIndent('  ').convert(state.toJson()),
      flush: true,
    );
    await tmp.rename(file.path);
  }
}
