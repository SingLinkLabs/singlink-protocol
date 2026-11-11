import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/client_controller.dart';
import '../format.dart';

/// Traffic / connections / uptime tiles, the SOCKS5 endpoint and the probe.
class StatsPanel extends StatelessWidget {
  const StatsPanel({super.key, required this.c});

  final ClientController c;

  @override
  Widget build(BuildContext context) {
    final on = c.isConnected;
    final s = c.status;
    final since = s.since ?? c.connectedAt;
    final uptime = on && since != null
        ? formatDuration(DateTime.now().difference(since))
        : '—';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: _Tile(
                icon: Icons.arrow_upward_rounded,
                label: '上傳',
                value: on ? formatRate(c.upRate) : '—',
                sub: '共 ${formatBytes(s.up)}',
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _Tile(
                icon: Icons.arrow_downward_rounded,
                label: '下載',
                value: on ? formatRate(c.downRate) : '—',
                sub: '共 ${formatBytes(s.down)}',
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: _Tile(
                icon: Icons.hub_rounded,
                label: '活動連線',
                value: on ? '${s.conns}' : '—',
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _Tile(
                icon: Icons.schedule_rounded,
                label: '已連線時間',
                value: uptime,
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        _ProxyCard(c: c),
      ],
    );
  }
}

class _Tile extends StatelessWidget {
  const _Tile({
    required this.icon,
    required this.label,
    required this.value,
    this.sub,
  });

  final IconData icon;
  final String label;
  final String value;
  final String? sub;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 16, color: cs.primary),
                const SizedBox(width: 6),
                Text(
                  label,
                  style: text.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: text.titleLarge?.copyWith(
                fontWeight: FontWeight.w700,
                fontFeatures: const [FontFeature.tabularFigures()],
              ),
            ),
            if (sub != null)
              Text(
                sub!,
                style: text.bodySmall?.copyWith(
                  color: cs.onSurfaceVariant,
                  fontFeatures: const [FontFeature.tabularFigures()],
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _ProxyCard extends StatelessWidget {
  const _ProxyCard({required this.c});

  final ClientController c;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final on = c.isConnected;
    final addr = c.activeListen;
    final probe = c.lastProbe;

    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 8, 14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text.rich(
                    TextSpan(
                      children: [
                        const TextSpan(text: 'SOCKS5 代理：'),
                        TextSpan(
                          text: addr,
                          style: const TextStyle(
                            fontFamily: 'Menlo',
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                    style: text.bodyLarge?.copyWith(
                      color: on ? null : cs.onSurfaceVariant,
                    ),
                  ),
                ),
                IconButton(
                  tooltip: '複製位址',
                  icon: const Icon(Icons.copy_rounded, size: 18),
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: addr));
                    if (!context.mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('已複製 $addr'),
                        duration: const Duration(seconds: 2),
                      ),
                    );
                  },
                ),
              ],
            ),
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Text(
                on
                    ? '在瀏覽器或系統「網路 › 代理伺服器」中，將 SOCKS 代理指向此位址即可使用。'
                    : '連線後，瀏覽器或系統的 SOCKS 代理可指向此位址。',
                style: text.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                OutlinedButton.icon(
                  onPressed: on && !c.probing ? c.probe : null,
                  icon: c.probing
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.speed_rounded, size: 18),
                  label: const Text('測試連線'),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: probe == null
                      ? const SizedBox.shrink()
                      : Text(
                          probe.ok
                              ? '延遲 ${probe.latencyMs} ms（HTTP ${probe.status}）'
                              : probe.error,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                          style: text.bodyMedium?.copyWith(
                            color: probe.ok ? cs.primary : cs.error,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
