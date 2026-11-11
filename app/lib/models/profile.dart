/// An imported `sl3://` server profile.
///
/// The fields mirror the `profile` object returned by `SL3ParseLink`; the raw
/// [link] is kept because `SL3Start` takes the link, not the parsed profile.
class Profile {
  Profile({
    required this.id,
    required this.link,
    required this.name,
    required this.server,
    required this.transport,
    required this.sni,
    required this.subject,
    required this.plan,
    required this.expiresAt,
    required this.caps,
    required this.addedAt,
  });

  final String id;
  final String link;
  final String name;

  /// `host:port`.
  final String server;

  /// `tls` or `tcp`.
  final String transport;
  final String sni;

  /// Hex-encoded subject identifier.
  final String subject;
  final int plan;

  /// Null when the link carries no expiry (`expiresAt` missing or 0).
  final DateTime? expiresAt;
  final List<String> caps;
  final DateTime addedAt;

  bool get isExpired =>
      expiresAt != null && expiresAt!.isBefore(DateTime.now());

  /// Display name; falls back to the server address when the link has none.
  String get displayName => name.trim().isEmpty ? server : name.trim();

  /// Builds a profile from the `profile` object of an `SL3ParseLink` reply.
  factory Profile.fromCore(
    String link,
    Map<String, dynamic> json, {
    String? id,
    DateTime? addedAt,
  }) {
    final now = DateTime.now();
    return Profile(
      id: id ?? now.microsecondsSinceEpoch.toRadixString(36),
      link: link.trim(),
      name: _str(json['name']),
      server: _str(json['server']),
      transport: _str(json['transport']),
      sni: _str(json['sni']),
      subject: _str(json['subject']),
      plan: _int(json['plan']),
      expiresAt: _unix(json['expiresAt']),
      caps: _strList(json['caps']),
      addedAt: addedAt ?? now,
    );
  }

  /// Persistence format (superset of the core's profile object).
  Map<String, dynamic> toJson() => {
    'id': id,
    'link': link,
    'name': name,
    'server': server,
    'transport': transport,
    'sni': sni,
    'subject': subject,
    'plan': plan,
    'expiresAt': expiresAt == null
        ? 0
        : expiresAt!.millisecondsSinceEpoch ~/ 1000,
    'caps': caps,
    'addedAt': addedAt.millisecondsSinceEpoch ~/ 1000,
  };

  factory Profile.fromJson(Map<String, dynamic> json) => Profile.fromCore(
    _str(json['link']),
    json,
    id: _str(json['id']).isEmpty ? null : _str(json['id']),
    addedAt: _unix(json['addedAt']),
  );
}

/// Result of `SL3ParseLink`: `{"ok":true,"profile":{...}}` or
/// `{"ok":false,"error":".."}`.
class ParseLinkResult {
  const ParseLinkResult._(this.profile, this.error);

  final Profile? profile;
  final String? error;

  bool get ok => profile != null;

  factory ParseLinkResult.failure(String error) =>
      ParseLinkResult._(null, error);

  factory ParseLinkResult.fromJson(String link, Map<String, dynamic> json) {
    final profile = json['profile'];
    if (json['ok'] == true && profile is Map<String, dynamic>) {
      return ParseLinkResult._(Profile.fromCore(link, profile), null);
    }
    final err = _str(json['error']);
    return ParseLinkResult._(null, err.isEmpty ? '無法解析連結' : err);
  }
}

String _str(Object? v) => v == null ? '' : v.toString();

int _int(Object? v) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? 0;
  return 0;
}

DateTime? _unix(Object? v) {
  final s = _int(v);
  return s <= 0 ? null : DateTime.fromMillisecondsSinceEpoch(s * 1000);
}

List<String> _strList(Object? v) =>
    v is List ? v.map((e) => e.toString()).toList() : const <String>[];
