import 'package:flutter/material.dart';

import '../../core/app_store.dart';
import '../../core/client_controller.dart';

/// Small sheet for the local SOCKS5 listen address.
Future<void> showSettingsSheet(BuildContext context, ClientController c) {
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    showDragHandle: true,
    constraints: const BoxConstraints(maxWidth: 520),
    builder: (_) => _SettingsSheet(c: c),
  );
}

class _SettingsSheet extends StatefulWidget {
  const _SettingsSheet({required this.c});
  final ClientController c;

  @override
  State<_SettingsSheet> createState() => _SettingsSheetState();
}

class _SettingsSheetState extends State<_SettingsSheet> {
  late final _ctrl = TextEditingController(text: widget.c.listen);
  String? _error;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final err = validateListen(_ctrl.text);
    if (err != null) {
      setState(() => _error = err);
      return;
    }
    await widget.c.setListen(_ctrl.text);
    if (mounted) Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final locked = widget.c.conn != ConnState.disconnected;
    return Padding(
      padding: EdgeInsets.fromLTRB(
        24,
        0,
        24,
        24 + MediaQuery.viewInsetsOf(context).bottom,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            '設定',
            style: text.titleLarge?.copyWith(fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _ctrl,
            enabled: !locked,
            autofocus: !locked,
            onSubmitted: (_) => _save(),
            style: const TextStyle(fontFamily: 'Menlo'),
            decoration: InputDecoration(
              labelText: '本機 SOCKS5 監聽位址',
              hintText: defaultListen,
              errorText: _error,
              helperText: locked
                  ? '請先中斷連線再修改'
                  : '預設 $defaultListen；改用 0.0.0.0 會讓區域網路內其他裝置也能使用',
              helperMaxLines: 2,
            ),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              TextButton(
                onPressed: locked
                    ? null
                    : () => setState(() {
                        _ctrl.text = defaultListen;
                        _error = null;
                      }),
                child: const Text('還原預設'),
              ),
              const Spacer(),
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('取消'),
              ),
              const SizedBox(width: 8),
              FilledButton(
                onPressed: locked ? null : _save,
                child: const Text('儲存'),
              ),
            ],
          ),
          if (widget.c.coreVersion != null) ...[
            const SizedBox(height: 16),
            Text(
              '核心 ${widget.c.coreVersion}',
              style: text.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ],
        ],
      ),
    );
  }
}
