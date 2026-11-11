import 'package:flutter/material.dart';

import '../core/client_controller.dart';
import 'theme.dart';
import 'widgets/connect_button.dart';
import 'widgets/core_missing_banner.dart';
import 'widgets/import_bar.dart';
import 'widgets/log_bar.dart';
import 'widgets/profile_card.dart';
import 'widgets/profile_list.dart';
import 'widgets/settings_sheet.dart';
import 'widgets/stats_panel.dart';

class HomePage extends StatelessWidget {
  const HomePage({super.key, required this.c});

  final ClientController c;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) => Scaffold(
        body: SafeArea(
          child: Column(
            children: [
              _Header(c: c),
              Expanded(
                child: LayoutBuilder(
                  builder: (context, box) =>
                      box.maxWidth >= 860 ? _wide(context) : _narrow(context),
                ),
              ),
              LogBar(c: c),
            ],
          ),
        ),
      ),
    );
  }

  Widget? _banner() => c.coreAvailable
      ? null
      : Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: CoreMissingBanner(location: c.service.location),
        );

  List<Widget> _profileColumn() => [
    ImportBar(onImport: c.importLink),
    const SizedBox(height: 16),
    if (c.selected != null) ...[
      ProfileCard(profile: c.selected!),
      const SizedBox(height: 16),
    ],
    ProfileList(
      profiles: c.profiles,
      selectedId: c.selected?.id,
      locked: c.conn != ConnState.disconnected,
      onSelect: c.select,
      onDelete: c.delete,
    ),
  ];

  Widget _wide(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ?_banner(),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 400,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _ConnectPanel(c: c),
                    const SizedBox(height: 16),
                    StatsPanel(c: c),
                  ],
                ),
              ),
              const SizedBox(width: 20),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: _profileColumn(),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _narrow(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              ?_banner(),
              _ConnectPanel(c: c),
              const SizedBox(height: 16),
              StatsPanel(c: c),
              const SizedBox(height: 16),
              ..._profileColumn(),
            ],
          ),
        ),
      ),
    );
  }
}

class _Header extends StatelessWidget {
  const _Header({required this.c});
  final ClientController c;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 14, 12, 8),
      child: Row(
        children: [
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              gradient: Brand.gradient,
              borderRadius: BorderRadius.circular(10),
            ),
            alignment: Alignment.center,
            child: const Text(
              'SL',
              style: TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w800,
                fontSize: 14,
                letterSpacing: 0.5,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Text(
            'SingLink 3.0',
            style: text.titleLarge?.copyWith(fontWeight: FontWeight.w800),
          ),
          const SizedBox(width: 10),
          if (c.coreVersion != null)
            Text(
              c.coreVersion!.protocol,
              style: text.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          const Spacer(),
          IconButton(
            tooltip: '設定',
            icon: const Icon(Icons.tune_rounded),
            onPressed: () => showSettingsSheet(context, c),
          ),
        ],
      ),
    );
  }
}

class _ConnectPanel extends StatelessWidget {
  const _ConnectPanel({required this.c});
  final ClientController c;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final profile = c.selected;
    final canConnect = c.coreAvailable && profile != null;

    final (title, color) = switch (c.conn) {
      ConnState.connected => ('已連線', cs.primary),
      ConnState.connecting => ('正在連線…', cs.onSurface),
      ConnState.disconnecting => ('正在中斷…', cs.onSurface),
      ConnState.disconnected => ('未連線', cs.onSurfaceVariant),
    };

    final String subtitle;
    if (!c.coreAvailable) {
      subtitle = '協議核心未載入';
    } else if (profile == null) {
      subtitle = '請先匯入 sl3:// 連結';
    } else {
      subtitle = profile.displayName;
    }

    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 28, 20, 22),
        child: Column(
          children: [
            ConnectButton(
              state: c.conn,
              enabled: canConnect || c.conn != ConnState.disconnected,
              onPressed: c.toggle,
            ),
            const SizedBox(height: 18),
            Text(
              title,
              style: text.titleLarge?.copyWith(
                color: color,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              subtitle,
              textAlign: TextAlign.center,
              overflow: TextOverflow.ellipsis,
              style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
            ),
            if (c.connectError != null && c.conn == ConnState.disconnected) ...[
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 10,
                ),
                decoration: BoxDecoration(
                  color: cs.errorContainer,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: SelectableText(
                  c.connectError!,
                  style: text.bodySmall?.copyWith(color: cs.onErrorContainer),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
