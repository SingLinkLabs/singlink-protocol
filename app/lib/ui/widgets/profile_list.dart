import 'package:flutter/material.dart';

import '../../models/profile.dart';
import '../format.dart';

/// All saved profiles: tap to select, trash icon to delete.
class ProfileList extends StatelessWidget {
  const ProfileList({
    super.key,
    required this.profiles,
    required this.selectedId,
    required this.locked,
    required this.onSelect,
    required this.onDelete,
  });

  final List<Profile> profiles;
  final String? selectedId;

  /// True while connected: selection cannot change.
  final bool locked;
  final ValueChanged<String> onSelect;
  final ValueChanged<String> onDelete;

  Future<void> _confirmDelete(BuildContext context, Profile p) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('刪除設定檔？'),
        content: Text('將刪除「${p.displayName}」（${p.server}），此操作無法復原。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
            ),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('刪除'),
          ),
        ],
      ),
    );
    if (ok == true) onDelete(p.id);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 6),
              child: Row(
                children: [
                  Text(
                    '設定檔',
                    style: text.titleSmall?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    '${profiles.length}',
                    style: text.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  ),
                  const Spacer(),
                  if (locked)
                    Text(
                      '中斷連線後可切換',
                      style: text.bodySmall?.copyWith(
                        color: cs.onSurfaceVariant,
                      ),
                    ),
                ],
              ),
            ),
            if (profiles.isEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 14),
                child: Text(
                  '尚未匯入任何設定檔。',
                  style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
                ),
              ),
            for (final p in profiles)
              _ProfileTile(
                profile: p,
                selected: p.id == selectedId,
                locked: locked,
                onTap: () => onSelect(p.id),
                onDelete: () => _confirmDelete(context, p),
              ),
          ],
        ),
      ),
    );
  }
}

class _ProfileTile extends StatelessWidget {
  const _ProfileTile({
    required this.profile,
    required this.selected,
    required this.locked,
    required this.onTap,
    required this.onDelete,
  });

  final Profile profile;
  final bool selected;
  final bool locked;
  final VoidCallback onTap;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final p = profile;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      child: Material(
        color: selected
            ? cs.primary.withValues(alpha: 0.10)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(12),
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: locked || selected ? null : onTap,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(10, 8, 4, 8),
            child: Row(
              children: [
                Icon(
                  selected
                      ? Icons.radio_button_checked_rounded
                      : Icons.radio_button_off_rounded,
                  size: 20,
                  color: selected ? cs.primary : cs.onSurfaceVariant,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        p.displayName,
                        overflow: TextOverflow.ellipsis,
                        style: text.bodyMedium?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        '${p.server} · ${transportLabel(p.transport)}'
                        '${p.isExpired ? ' · 已過期' : ''}',
                        overflow: TextOverflow.ellipsis,
                        style: text.bodySmall?.copyWith(
                          color: p.isExpired ? cs.error : cs.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  tooltip: '刪除',
                  onPressed: locked && selected ? null : onDelete,
                  icon: const Icon(Icons.delete_outline_rounded, size: 20),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
