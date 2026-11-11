// App state + orchestration: profiles, connect/disconnect, status polling,
// probe, log. The UI only listens to this ChangeNotifier.

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../models/core_status.dart';
import '../models/profile.dart';
import 'app_store.dart';
import 'sl3_service.dart';

enum ConnState { disconnected, connecting, connected, disconnecting }

enum LogLevel { info, success, error }

class LogEntry {
  LogEntry(this.message, this.level) : time = DateTime.now();
  final DateTime time;
  final String message;
  final LogLevel level;
}

const probeUrl = 'https://www.gstatic.com/generate_204';
const probeTimeoutMs = 8000;

/// Returns an error message, or null if [s] is a valid `host:port`.
String? validateListen(String s) {
  final v = s.trim();
  final i = v.lastIndexOf(':');
  if (i <= 0 || i == v.length - 1) return '格式應為 主機:埠，例如 127.0.0.1:1080';
  final port = int.tryParse(v.substring(i + 1));
  if (port == null || port < 1 || port > 65535) return '埠號須介於 1–65535';
  final host = v.substring(0, i);
  if (host.contains(' ')) return '主機不可包含空白';
  return null;
}

class ClientController extends ChangeNotifier {
  ClientController({required this.service, required this.store});

  final Sl3Service service;
  final AppStore store;

  AppState _state = AppState();
  bool loaded = false;
  CoreVersion? coreVersion;

  ConnState conn = ConnState.disconnected;
  CoreStatus status = CoreStatus.idle;
  double upRate = 0; // bytes/s
  double downRate = 0;
  String? connectError;
  DateTime? connectedAt;

  bool probing = false;
  ProbeResult? lastProbe;

  final List<LogEntry> logs = [];

  Timer? _poll;
  bool _pollInFlight = false;
  DateTime? _sampleAt;
  int _sampleUp = 0;
  int _sampleDown = 0;
  bool _disposed = false;

  List<Profile> get profiles => List.unmodifiable(_state.profiles);
  String get listen => _state.listen;
  bool get coreAvailable => service.available;
  bool get busy =>
      conn == ConnState.connecting || conn == ConnState.disconnecting;
  bool get isConnected => conn == ConnState.connected;

  Profile? get selected {
    for (final p in _state.profiles) {
      if (p.id == _state.selectedId) return p;
    }
    return _state.profiles.isEmpty ? null : _state.profiles.first;
  }

  /// The SOCKS5 endpoint actually in use (core's report wins over settings).
  String get activeListen =>
      status.listen.isNotEmpty ? status.listen : _state.listen;

  Future<void> init() async {
    _state = await store.load();
    loaded = true;
    if (service.available) {
      log('已載入協議核心：${service.location.path}');
      try {
        coreVersion = await service.version();
        log('核心版本 $coreVersion');
      } catch (e) {
        log('讀取核心版本失敗：$e', LogLevel.error);
      }
    } else {
      log('找不到協議核心 libsl3.dylib', LogLevel.error);
    }
    _notify();
  }

  void log(String message, [LogLevel level = LogLevel.info]) {
    logs.add(LogEntry(message, level));
    if (logs.length > 300) logs.removeRange(0, logs.length - 300);
    _notify();
  }

  // ---- profiles -----------------------------------------------------------

  /// Parses and stores [link]. Returns an error message or null on success.
  Future<String?> importLink(String link) async {
    final trimmed = link.trim();
    if (trimmed.isEmpty) return '請先貼上 sl3:// 連結';
    if (!trimmed.toLowerCase().startsWith('sl3://')) {
      return '連結須以 sl3:// 開頭';
    }
    for (final p in _state.profiles) {
      if (p.link == trimmed) {
        await select(p.id);
        log('此連結已存在，已選取「${p.displayName}」');
        return null;
      }
    }
    final res = await service.parseLink(trimmed);
    if (!res.ok) {
      log('匯入失敗：${res.error}', LogLevel.error);
      return res.error;
    }
    final profile = res.profile!;
    _state.profiles.add(profile);
    _state.selectedId = profile.id;
    await _save();
    log('已匯入「${profile.displayName}」（${profile.server}）', LogLevel.success);
    return null;
  }

  Future<void> select(String id) async {
    if (conn != ConnState.disconnected) return;
    _state.selectedId = id;
    await _save();
  }

  Future<void> delete(String id) async {
    final idx = _state.profiles.indexWhere((p) => p.id == id);
    if (idx < 0) return;
    if (conn != ConnState.disconnected && selected?.id == id) {
      log('連線中無法刪除目前使用的設定檔', LogLevel.error);
      return;
    }
    final removed = _state.profiles.removeAt(idx);
    if (_state.selectedId == id) {
      _state.selectedId = _state.profiles.isEmpty
          ? null
          : _state.profiles.first.id;
    }
    await _save();
    log('已刪除「${removed.displayName}」');
  }

  Future<void> setListen(String value) async {
    _state.listen = value.trim();
    await _save();
    log('本機代理位址已設為 ${_state.listen}');
  }

  // ---- connection ---------------------------------------------------------

  Future<void> toggle() async {
    if (busy) return;
    if (conn == ConnState.connected) {
      await disconnect();
    } else {
      await connect();
    }
  }

  Future<void> connect() async {
    final profile = selected;
    if (profile == null || busy || !service.available) return;
    conn = ConnState.connecting;
    connectError = null;
    lastProbe = null;
    log('正在連線「${profile.displayName}」…');
    final res = await service.start(link: profile.link, listen: _state.listen);
    if (_disposed) return;
    if (!res.ok) {
      conn = ConnState.disconnected;
      connectError = res.error.isEmpty ? '連線失敗' : res.error;
      log('連線失敗：$connectError', LogLevel.error);
      return;
    }
    conn = ConnState.connected;
    connectedAt = DateTime.now();
    status = CoreStatus.idle;
    upRate = downRate = 0;
    _sampleAt = null;
    log('已連線，SOCKS5 代理 ${_state.listen}', LogLevel.success);
    _startPolling();
  }

  Future<void> disconnect() async {
    if (busy) return;
    conn = ConnState.disconnecting;
    _stopPolling();
    _notify();
    final res = await service.stop();
    if (_disposed) return;
    if (!res.ok) log('停止時發生錯誤：${res.error}', LogLevel.error);
    _resetDisconnected();
    log('已中斷連線');
  }

  void _resetDisconnected() {
    conn = ConnState.disconnected;
    connectedAt = null;
    upRate = downRate = 0;
    _sampleAt = null;
    status = CoreStatus(
      running: false,
      listen: '',
      up: status.up,
      down: status.down,
      conns: 0,
      since: null,
      lastError: status.lastError,
    );
  }

  void _startPolling() {
    _stopPolling();
    _poll = Timer.periodic(const Duration(seconds: 1), (_) => _pollOnce());
    _pollOnce();
  }

  void _stopPolling() {
    _poll?.cancel();
    _poll = null;
  }

  Future<void> _pollOnce() async {
    if (_pollInFlight || conn != ConnState.connected) return;
    _pollInFlight = true;
    try {
      final s = await service.status();
      if (_disposed || conn != ConnState.connected) return;
      final now = DateTime.now();
      if (_sampleAt != null) {
        final dt = now.difference(_sampleAt!).inMicroseconds / 1e6;
        if (dt > 0) {
          upRate = ((s.up - _sampleUp).clamp(0, 1 << 62)) / dt;
          downRate = ((s.down - _sampleDown).clamp(0, 1 << 62)) / dt;
        }
      }
      _sampleAt = now;
      _sampleUp = s.up;
      _sampleDown = s.down;
      if (s.lastError.isNotEmpty && s.lastError != status.lastError) {
        log('核心：${s.lastError}', LogLevel.error);
      }
      status = s;
      if (!s.running) {
        _stopPolling();
        _resetDisconnected();
        connectError = s.lastError.isEmpty ? '核心已停止運行' : s.lastError;
        log('連線已中斷：$connectError', LogLevel.error);
      }
      _notify();
    } catch (e) {
      log('讀取狀態失敗：$e', LogLevel.error);
    } finally {
      _pollInFlight = false;
    }
  }

  Future<void> probe() async {
    if (probing || conn != ConnState.connected) return;
    probing = true;
    lastProbe = null;
    log('測試連線 $probeUrl …');
    final r = await service.probe(probeUrl, timeoutMs: probeTimeoutMs);
    if (_disposed) return;
    probing = false;
    lastProbe = r;
    if (r.ok) {
      log('測試成功：HTTP ${r.status}，延遲 ${r.latencyMs} ms', LogLevel.success);
    } else {
      log('測試失敗：${r.error}', LogLevel.error);
    }
  }

  Future<void> _save() async {
    try {
      await store.save(_state);
    } catch (e) {
      logs.add(LogEntry('儲存設定失敗：$e', LogLevel.error));
    }
    _notify();
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _stopPolling();
    super.dispose();
  }
}
