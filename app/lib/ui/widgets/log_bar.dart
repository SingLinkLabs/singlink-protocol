import 'package:flutter/material.dart';

import '../../core/client_controller.dart';
import '../format.dart';

/// One-line status/log footer; click to open the full log.
class LogBar extends StatelessWidget {
  const LogBar({super.key, required this.c});

  final ClientController c;

  Color _color(ColorScheme cs, LogLevel l) => switch (l) {
    LogLevel.info => cs.onSurfaceVariant,
    LogLevel.success => cs.primary,
    LogLevel.error => cs.error,
  };

  void _openLog(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (ctx) {
        final cs = Theme.of(ctx).colorScheme;
        final entries = c.logs.reversed.toList();
        return AlertDialog(
          title: const Text('紀錄'),
          content: SizedBox(
            width: 560,
            height: 380,
            child: entries.isEmpty
                ? const Center(child: Text('暫無紀錄'))
                : SelectionArea(
                    child: ListView.builder(
                      itemCount: entries.length,
                      itemBuilder: (_, i) {
                        final e = entries[i];
                        return Padding(
                          padding: const EdgeInsets.symmetric(vertical: 3),
                          child: Text(
                            '${formatClock(e.time)}  ${e.message}',
                            style: TextStyle(
                              fontFamily: 'Menlo',
                              fontSize: 12,
                              color: _color(cs, e.level),
                            ),
                          ),
                        );
                      },
                    ),
                  ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('關閉'),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final last = c.logs.isEmpty ? null : c.logs.last;
    final dot = switch (c.conn) {
      ConnState.connected => cs.primary,
      ConnState.disconnected => cs.outline,
      _ => cs.tertiary,
    };
    return Material(
      color: cs.surfaceContainer,
      child: InkWell(
        onTap: () => _openLog(context),
        child: Container(
          height: 34,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          decoration: BoxDecoration(
            border: Border(top: BorderSide(color: cs.outlineVariant)),
          ),
          child: Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(color: dot, shape: BoxShape.circle),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  last == null
                      ? '就緒'
                      : '${formatClock(last.time)}  ${last.message}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: last == null
                        ? cs.onSurfaceVariant
                        : _color(cs, last.level),
                  ),
                ),
              ),
              if (c.coreVersion != null)
                Text(
                  'core ${c.coreVersion!.version}',
                  style: Theme.of(
                    context,
                  ).textTheme.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                ),
              const SizedBox(width: 8),
              Icon(Icons.notes_rounded, size: 16, color: cs.onSurfaceVariant),
            ],
          ),
        ),
      ),
    );
  }
}
