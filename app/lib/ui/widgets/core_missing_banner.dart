import 'package:flutter/material.dart';

import '../../core/sl3_bindings.dart';

/// Shown instead of crashing when libsl3 cannot be loaded.
class CoreMissingBanner extends StatelessWidget {
  const CoreMissingBanner({super.key, required this.location});

  final Sl3LibLocation location;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final mono = text.bodySmall?.copyWith(
      fontFamily: 'Menlo',
      color: cs.onErrorContainer,
    );
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 14),
      decoration: BoxDecoration(
        color: cs.errorContainer,
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.extension_off_rounded, color: cs.onErrorContainer),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '找不到協議核心 libsl3.dylib',
                  style: text.titleSmall?.copyWith(
                    color: cs.onErrorContainer,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '介面可正常使用，但無法解析連結或連線。請將核心放到以下路徑：',
                  style: text.bodySmall?.copyWith(color: cs.onErrorContainer),
                ),
                const SizedBox(height: 6),
                SelectableText(location.expectedPath, style: mono),
                if (location.searched.length > 1) ...[
                  const SizedBox(height: 8),
                  Text(
                    '或設定環境變數 SL3_LIB，或於開發時放在 ../core/build/。已搜尋：',
                    style: text.bodySmall?.copyWith(color: cs.onErrorContainer),
                  ),
                  const SizedBox(height: 4),
                  SelectableText(
                    location.searched.skip(1).join('\n'),
                    style: mono,
                  ),
                ],
                if (location.errors.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  Text(
                    '載入錯誤：',
                    style: text.bodySmall?.copyWith(color: cs.onErrorContainer),
                  ),
                  SelectableText(location.errors.join('\n'), style: mono),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
