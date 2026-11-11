/// Display formatting helpers (pure functions, unit-tested).
library;

String formatBytes(num bytes) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var v = bytes.toDouble();
  var i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  final digits = i == 0 || v >= 100 ? 0 : (v >= 10 ? 1 : 2);
  return '${v.toStringAsFixed(digits)} ${units[i]}';
}

String formatRate(num bytesPerSecond) => '${formatBytes(bytesPerSecond)}/s';

/// `1:02:03`, `02:03`.
String formatDuration(Duration d) {
  if (d.isNegative) d = Duration.zero;
  String two(int n) => n.toString().padLeft(2, '0');
  final h = d.inHours;
  final m = d.inMinutes.remainder(60);
  final s = d.inSeconds.remainder(60);
  if (d.inDays > 0) {
    return '${d.inDays} 天 ${two(h.remainder(24))}:${two(m)}:${two(s)}';
  }
  return h > 0 ? '$h:${two(m)}:${two(s)}' : '${two(m)}:${two(s)}';
}

/// `2026-11-12`.
String formatDate(DateTime t) {
  String two(int n) => n.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)}';
}

/// `14:03:22`.
String formatClock(DateTime t) {
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(t.hour)}:${two(t.minute)}:${two(t.second)}';
}

String transportLabel(String t) => switch (t.toLowerCase()) {
  'tls' => 'TLS',
  'tcp' => 'TCP',
  '' => '—',
  _ => t.toUpperCase(),
};
