#!/bin/bash
#
#  build.sh
#  FileCrypt
#
#  Copyright (c) 2026 Irshad
#  SPDX-License-Identifier: MIT
#
#
# Builds FileCrypt.app and the `fcrypt` command-line tool.
#
#   ./build.sh              # release build
#   ./build.sh debug        # debug build
#   ./build.sh release run  # build, then launch the app
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

CONFIGURATION="${1:-release}"
ACTION="${2:-}"

BUILD_DIR="$PROJECT_DIR/build"
APP_DIR="$BUILD_DIR/FileCrypt.app"
ICONSET_DIR="$BUILD_DIR/FileCrypt.iconset"
LOG_FILE="$BUILD_DIR/swift-build.log"

mkdir -p "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------
echo "==> Building ($CONFIGURATION)"

# Some locked-down environments forbid nested sandboxing, which makes SwiftPM's
# own build sandbox fail. Detect that specific failure and retry once without
# it rather than making everyone else give up the protection.
if ! swift build -c "$CONFIGURATION" --product FileCrypt >"$LOG_FILE" 2>&1; then
	if grep -q "sandbox_apply" "$LOG_FILE"; then
		echo "    (SwiftPM sandbox unavailable here; retrying with --disable-sandbox)"
		swift build -c "$CONFIGURATION" --disable-sandbox --product FileCrypt
	else
		cat "$LOG_FILE" >&2
		exit 1
	fi
fi

if ! swift build -c "$CONFIGURATION" --product fcrypt >>"$LOG_FILE" 2>&1; then
	if grep -q "sandbox_apply" "$LOG_FILE"; then
		swift build -c "$CONFIGURATION" --disable-sandbox --product fcrypt
	else
		cat "$LOG_FILE" >&2
		exit 1
	fi
fi

BIN_DIR="$(swift build -c "$CONFIGURATION" --show-bin-path 2>/dev/null || echo "$PROJECT_DIR/.build/$CONFIGURATION")"

# ---------------------------------------------------------------------------
# Icon
# ---------------------------------------------------------------------------
if [ ! -f "$BUILD_DIR/AppIcon.icns" ]; then
	echo "==> Rendering the app icon"
	rm -rf "$ICONSET_DIR"
	swift "$PROJECT_DIR/Scripts/make_icon.swift" "$ICONSET_DIR" >/dev/null
	iconutil -c icns "$ICONSET_DIR" -o "$BUILD_DIR/AppIcon.icns"
fi

# ---------------------------------------------------------------------------
# Assemble the bundle
# ---------------------------------------------------------------------------
echo "==> Assembling FileCrypt.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$BIN_DIR/FileCrypt" "$APP_DIR/Contents/MacOS/FileCrypt"
cp "$PROJECT_DIR/Resources/Info.plist" "$APP_DIR/Contents/Info.plist"
cp "$BUILD_DIR/AppIcon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"
printf 'APPL????' > "$APP_DIR/Contents/PkgInfo"

# Licence texts travel with the binary. The MIT licence requires its notice to
# accompany the software, and the bundled Argon2 keeps its own terms.
mkdir -p "$APP_DIR/Contents/Resources/Licenses"
cp "$PROJECT_DIR/LICENSE"                    "$APP_DIR/Contents/Resources/Licenses/LICENSE"
cp "$PROJECT_DIR/THIRD-PARTY-NOTICES.md"     "$APP_DIR/Contents/Resources/Licenses/THIRD-PARTY-NOTICES.md"
cp "$PROJECT_DIR/Sources/CArgon2/LICENSE"    "$APP_DIR/Contents/Resources/Licenses/LICENSE-Argon2.txt"

cp "$BIN_DIR/fcrypt" "$BUILD_DIR/fcrypt"

# Ad-hoc signature. Good enough to launch locally; replace "-" with a Developer
# ID to distribute. Signing is optional, so do not fail the build over it.
if command -v codesign >/dev/null 2>&1; then
	echo "==> Signing (ad-hoc)"
	codesign --force --deep --sign - "$APP_DIR" >/dev/null 2>&1 || \
		echo "    (ad-hoc signing failed; the app still runs locally)"
fi

# Refresh Launch Services so Finder picks up the new icon straight away.
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
	-f "$APP_DIR" >/dev/null 2>&1 || true

echo
echo "Done."
echo "  App: $APP_DIR"
echo "  CLI: $BUILD_DIR/fcrypt"

if [ "$ACTION" = "run" ]; then
	echo
	echo "==> Launching"
	open "$APP_DIR"
fi
