import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Paste / import an `sl3://` link.
class ImportBar extends StatefulWidget {
  const ImportBar({super.key, required this.onImport, this.enabled = true});

  /// Returns an error message, or null on success.
  final Future<String?> Function(String link) onImport;
  final bool enabled;

  @override
  State<ImportBar> createState() => _ImportBarState();
}

class _ImportBarState extends State<ImportBar> {
  final _ctrl = TextEditingController();
  String? _error;
  bool _working = false;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _submit(String link) async {
    if (_working) return;
    setState(() {
      _working = true;
      _error = null;
    });
    final err = await widget.onImport(link);
    if (!mounted) return;
    setState(() {
      _working = false;
      _error = err;
      if (err == null) _ctrl.clear();
    });
  }

  Future<void> _fromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (!mounted) return;
    if (text.isEmpty) {
      setState(() => _error = '剪貼簿沒有文字');
      return;
    }
    _ctrl.text = text;
    await _submit(text);
  }

  @override
  Widget build(BuildContext context) {
    final enabled = widget.enabled && !_working;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              '匯入設定檔',
              style: Theme.of(
                context,
              ).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _ctrl,
              enabled: enabled,
              onSubmitted: _submit,
              style: const TextStyle(fontFamily: 'Menlo', fontSize: 13),
              decoration: InputDecoration(
                hintText: '貼上 sl3:// 連結',
                prefixIcon: const Icon(Icons.link_rounded, size: 20),
                errorText: _error,
                errorMaxLines: 3,
              ),
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: enabled ? _fromClipboard : null,
                    icon: const Icon(Icons.content_paste_rounded, size: 18),
                    label: const Text('從剪貼簿匯入'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: enabled ? () => _submit(_ctrl.text) : null,
                    icon: _working
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.add_rounded, size: 18),
                    label: const Text('匯入'),
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
