import 'package:flutter/material.dart';

import '../../core/client_controller.dart';
import '../theme.dart';

/// The big round connect / disconnect toggle.
class ConnectButton extends StatelessWidget {
  const ConnectButton({
    super.key,
    required this.state,
    required this.enabled,
    required this.onPressed,
    this.size = 168,
  });

  final ConnState state;
  final bool enabled;
  final VoidCallback onPressed;
  final double size;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final on = state == ConnState.connected;
    final busy =
        state == ConnState.connecting || state == ConnState.disconnecting;
    final active = on || state == ConnState.connecting;

    final label = switch (state) {
      ConnState.disconnected => '連線',
      ConnState.connecting => '連線中…',
      ConnState.connected => '中斷連線',
      ConnState.disconnecting => '中斷中…',
    };

    return Semantics(
      button: true,
      enabled: enabled && !busy,
      label: label,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOutCubic,
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: active ? Brand.gradient : null,
          color: active ? null : cs.surfaceContainer,
          border: active
              ? null
              : Border.all(color: cs.outlineVariant, width: 1.5),
          boxShadow: on
              ? [
                  BoxShadow(
                    color: Brand.primary.withValues(alpha: 0.35),
                    blurRadius: 36,
                    spreadRadius: 2,
                  ),
                ]
              : const [],
        ),
        child: Material(
          type: MaterialType.transparency,
          shape: const CircleBorder(),
          clipBehavior: Clip.antiAlias,
          child: InkWell(
            onTap: enabled && !busy ? onPressed : null,
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  SizedBox(
                    width: size * 0.32,
                    height: size * 0.32,
                    child: busy
                        ? Padding(
                            padding: EdgeInsets.all(size * 0.04),
                            child: CircularProgressIndicator(
                              strokeWidth: 3,
                              color: active ? Colors.white : cs.primary,
                            ),
                          )
                        : Icon(
                            Icons.power_settings_new_rounded,
                            size: size * 0.32,
                            color: active
                                ? Colors.white
                                : (enabled
                                      ? cs.primary
                                      : cs.onSurface.withValues(alpha: 0.3)),
                          ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    label,
                    style: Theme.of(context).textTheme.labelLarge?.copyWith(
                      color: active
                          ? Colors.white
                          : cs.onSurface.withValues(
                              alpha: enabled ? 0.8 : 0.35,
                            ),
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
