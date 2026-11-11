import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'core/app_store.dart';
import 'core/client_controller.dart';
import 'core/sl3_service.dart';
import 'ui/home_page.dart';
import 'ui/theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Locating the core never throws; a missing library becomes a UI banner.
  final controller = ClientController(
    service: Sl3Service.locate(),
    store: AppStore.standard(),
  )..init();
  runApp(Sl3App(controller: controller));
}

/// Traditional Chinese (Hong Kong) — also drives correct CJK glyph selection.
const appLocale = Locale.fromSubtags(
  languageCode: 'zh',
  scriptCode: 'Hant',
  countryCode: 'HK',
);

class Sl3App extends StatelessWidget {
  const Sl3App({super.key, required this.controller});

  final ClientController controller;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SingLink 3.0',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      themeMode: ThemeMode.system,
      locale: appLocale,
      supportedLocales: const [
        appLocale,
        Locale.fromSubtags(
          languageCode: 'zh',
          scriptCode: 'Hant',
          countryCode: 'TW',
        ),
        Locale('en'),
      ],
      localizationsDelegates: GlobalMaterialLocalizations.delegates,
      home: HomePage(c: controller),
    );
  }
}
