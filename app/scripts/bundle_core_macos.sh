#!/bin/bash
# Copies the Go protocol core (libsl3.dylib) into <App>.app/Contents/Frameworks
# and code-signs it.
#
# Two modes:
#   --xcode                 Run from the Runner target's "Bundle libsl3 core"
#                           build phase (automatic on `flutter build macos` /
#                           `flutter run -d macos`). Xcode signs the whole app
#                           afterwards, so only the dylib is signed here.
#   [debug|profile|release] Standalone, after `flutter build macos --<mode>`.
#                           Copies, signs the dylib, then re-signs the .app with
#                           the matching entitlements. Default: release.
#
# Environment:
#   SL3_CORE_LIB        source dylib (default: <repo>/core/build/libsl3.dylib)
#   SL3_REQUIRE_CORE=1  fail instead of warning when the dylib is missing
#   CODESIGN_IDENTITY   standalone mode only (default "-" = ad-hoc)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_SRC="${SL3_CORE_LIB:-$APP_DIR/../core/build/libsl3.dylib}"
LIB_NAME="libsl3.dylib"

warn() { echo "warning: [sl3] $*" >&2; }
die() { echo "error: [sl3] $*" >&2; exit 1; }

missing_core() {
  if [[ "${SL3_REQUIRE_CORE:-0}" == "1" ]]; then
    die "core library not found at $LIB_SRC"
  fi
  warn "core library not found at $LIB_SRC — app will start and show the 'libsl3.dylib missing' banner."
  exit 0
}

sign_dylib() { # $1 = dylib, $2 = identity
  local id="$2"
  if [[ -z "$id" ]]; then id="-"; fi
  codesign --force --sign "$id" --timestamp=none "$1"
}

if [[ "${1:-}" == "--xcode" ]]; then
  : "${BUILT_PRODUCTS_DIR:?must run inside an Xcode build phase}"
  : "${FRAMEWORKS_FOLDER_PATH:?must run inside an Xcode build phase}"
  [[ -f "$LIB_SRC" ]] || missing_core
  DEST_DIR="$BUILT_PRODUCTS_DIR/$FRAMEWORKS_FOLDER_PATH"
  mkdir -p "$DEST_DIR"
  cp -f "$LIB_SRC" "$DEST_DIR/$LIB_NAME"
  chmod 755 "$DEST_DIR/$LIB_NAME"
  if [[ "${CODE_SIGNING_ALLOWED:-YES}" != "NO" ]]; then
    sign_dylib "$DEST_DIR/$LIB_NAME" "${EXPANDED_CODE_SIGN_IDENTITY:-}"
  fi
  echo "[sl3] bundled $LIB_SRC -> $DEST_DIR/$LIB_NAME"
  exit 0
fi

MODE="$(echo "${1:-release}" | tr '[:upper:]' '[:lower:]')"
case "$MODE" in
  debug)   CONFIG=Debug;   ENT="$APP_DIR/macos/Runner/DebugProfile.entitlements" ;;
  profile) CONFIG=Profile; ENT="$APP_DIR/macos/Runner/DebugProfile.entitlements" ;;
  release) CONFIG=Release; ENT="$APP_DIR/macos/Runner/Release.entitlements" ;;
  *) die "usage: $0 [--xcode | debug | profile | release]" ;;
esac

APP="$APP_DIR/build/macos/Build/Products/$CONFIG/sl3_client.app"
[[ -d "$APP" ]] || die "$APP not found — run: flutter build macos --$MODE"
[[ -f "$LIB_SRC" ]] || missing_core

ID="${CODESIGN_IDENTITY:--}"
mkdir -p "$APP/Contents/Frameworks"
cp -f "$LIB_SRC" "$APP/Contents/Frameworks/$LIB_NAME"
chmod 755 "$APP/Contents/Frameworks/$LIB_NAME"
sign_dylib "$APP/Contents/Frameworks/$LIB_NAME" "$ID"
# Contents changed, so the outer signature must be regenerated. Nested
# frameworks are already signed by the Flutter build; no --deep needed.
codesign --force --sign "$ID" --timestamp=none --entitlements "$ENT" "$APP"
codesign --verify --strict "$APP"
echo "[sl3] bundled $(lipo -archs "$APP/Contents/Frameworks/$LIB_NAME" 2>/dev/null || echo '?') $LIB_NAME into $APP"
