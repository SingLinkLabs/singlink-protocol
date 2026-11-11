import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sl3_client/core/app_store.dart';
import 'package:sl3_client/core/client_controller.dart';
import 'package:sl3_client/core/sl3_service.dart';
import 'package:sl3_client/main.dart';
import 'package:sl3_client/models/profile.dart';
import 'package:sl3_client/ui/widgets/profile_card.dart';

void main() {
  testWidgets('ProfileCard shows parsed profile', (tester) async {
    final p = Profile.fromCore('sl3://x', {
      'name': 'Tokyo',
      'server': 'jp.example.com:443',
      'transport': 'tls',
      'plan': 1,
      'expiresAt': 0,
      'caps': ['tcp', 'udp'],
    });
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: ProfileCard(profile: p)),
      ),
    );
    expect(find.text('Tokyo'), findsOneWidget);
    expect(find.text('jp.example.com:443'), findsOneWidget);
    expect(find.text('TLS'), findsOneWidget);
    expect(find.text('UDP'), findsOneWidget);
    expect(find.text('不限期'), findsOneWidget);
  });

  testWidgets('app starts without the core and shows the banner', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1100, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);

    final dir = await tester.runAsync(
      () => Directory.systemTemp.createTemp('sl3_widget_test'),
    );
    final c = ClientController(
      service: Sl3Service.unavailable(
        searched: [
          '/Applications/SingLink 3.0.app/Contents/Frameworks/libsl3.dylib',
        ],
      ),
      store: AppStore(File('${dir!.path}/state.json')),
    );
    await tester.runAsync(c.init);
    await tester.pumpWidget(Sl3App(controller: c));
    await tester.pumpAndSettle();

    expect(find.text('找不到協議核心 libsl3.dylib'), findsOneWidget);
    expect(
      find.textContaining('Contents/Frameworks/libsl3.dylib'),
      findsOneWidget,
    );
    expect(find.text('從剪貼簿匯入'), findsOneWidget);
    expect(find.text('未連線'), findsOneWidget);
    expect(find.textContaining('SOCKS5 代理：'), findsOneWidget);

    c.dispose();
    await tester.runAsync(() => dir.delete(recursive: true));
  });
}
