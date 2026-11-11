# SingLink 3.0 — desktop client shell (`sl3_client`)

Flutter UI over the Go protocol core `libsl3` (C ABI, loaded via `dart:ffi`).
macOS is the supported target; the android/ios folders are scaffolding only.

The app is plugin-free (only `ffi` + `flutter_localizations` from the SDK), so it
builds without CocoaPods or Swift Package Manager.

## Build

```bash
cd app
flutter pub get --offline
flutter analyze
flutter test
flutter build macos --debug      # or --release
open build/macos/Build/Products/Debug/sl3_client.app
```

Build the core first (`core/build/libsl3.dylib`, `go build -buildmode=c-shared`)
and it is bundled automatically (see below). Without it the app still starts and
shows the banner 「找不到協議核心 libsl3.dylib」 with the expected path.

## How the core library is found (`lib/core/sl3_bindings.dart`)

Tried in order; the first file that opens and exports all `SL3*` symbols wins:

1. `sl3_client.app/Contents/Frameworks/libsl3.dylib` (bundled)
2. `$SL3_LIB` — full path to a dylib (handy with `flutter run`)
3. Dev fallbacks: `<cwd>/../core/build/libsl3.dylib`, and
   `core/build/libsl3.dylib` under any ancestor of the executable — i.e.
   `singlink-protocol-3/core/build/libsl3.dylib` when running from `app/build/`.

Debug/Profile builds run **without** the App Sandbox so (2) and (3) work.
Release builds are sandboxed and in practice load only from (1).

## Bundling (`scripts/bundle_core_macos.sh`)

- **Automatic:** the Runner target has a build phase *Bundle libsl3 core* that
  runs `scripts/bundle_core_macos.sh --xcode` during every `flutter build macos`
  / `flutter run -d macos`. It copies `../core/build/libsl3.dylib` into
  `Contents/Frameworks/` and signs it with the build's identity; Xcode then
  signs the app. If the dylib is missing it only warns.
- **Manual / post-build:** `scripts/bundle_core_macos.sh [debug|profile|release]`
  copies the dylib into an already built app and re-signs the app with the
  matching entitlements (ad-hoc by default, `CODESIGN_IDENTITY=...` to override).

Options: `SL3_CORE_LIB=/path/libsl3.dylib` overrides the source,
`SL3_REQUIRE_CORE=1` makes a missing core a build error.

Note: a stale `libsl3.dylib` stays in an incremental build's `Frameworks/` after
the source is deleted; `flutter clean` (or delete the .app) to drop it.

## Entitlements

Both `macos/Runner/DebugProfile.entitlements` and `Release.entitlements` have
`com.apple.security.network.client` and `com.apple.security.network.server`
(the core opens a local SOCKS5 listener and outbound connections).
Deployment target is macOS 12.0 (current Xcode rejects 10.15).

## Data

Profiles and settings: `~/Library/Application Support/com.singlinklabs.sl3Client/state.json`
(Release/sandboxed: inside `~/Library/Containers/com.singlinklabs.sl3Client/Data/`).

## Layout

```
lib/main.dart                     app + theme + zh-Hant locale
lib/core/sl3_bindings.dart        raw FFI bindings, library search
lib/core/sl3_service.dart         Isolate.run wrapper, JSON decoding
lib/core/client_controller.dart   state: connect/disconnect, 1 s status poll, probe, log
lib/core/app_store.dart           JSON persistence
lib/models/profile.dart           Profile + SL3ParseLink reply
lib/models/core_status.dart       Status / Probe / Op / Version replies
lib/ui/                           home page, theme, formatting, widgets/
test/                             parsing/unit tests, widget tests, FFI test vs a C mock
```

`test/ffi_mock_test.dart` compiles `test/fixtures/mock_libsl3.c` with `cc` and
drives every binding through the real isolate + FFI path (skipped if no `cc`).
