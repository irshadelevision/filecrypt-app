#!/bin/bash
#
#  make_dmg.sh
#  FileCrypt
#
#  Copyright (c) 2026 Irshad Ibrahim
#  SPDX-License-Identifier: MIT
#
# Builds a distributable disk image containing FileCrypt.app and the fcrypt
# command-line tool.
#
#   ./Scripts/make_dmg.sh [version] [output-directory]
#
# Defaults to version 1.0.0 and ./build.
#
# The image is laid out the way a macOS user expects: the app on the left, an
# Applications symlink on the right, and a short note explaining that Gatekeeper
# will complain. The licence texts are included next to the app rather than only
# inside the bundle, because a recipient should be able to read the terms before
# running anything.
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

VERSION="${1:-1.0.0}"
OUTPUT_DIR="${2:-$PROJECT_DIR/build}"
APP="$PROJECT_DIR/build/FileCrypt.app"
CLI="$PROJECT_DIR/build/fcrypt"

if [ ! -d "$APP" ]; then
	echo "FileCrypt.app not found at $APP; run ./build.sh release first" >&2
	exit 1
fi
if [ ! -x "$CLI" ]; then
	echo "fcrypt not found at $CLI; run ./build.sh release first" >&2
	exit 1
fi

VOLUME_NAME="FileCrypt $VERSION"
DMG_NAME="FileCrypt-$VERSION-macos-arm64.dmg"
DMG_PATH="$OUTPUT_DIR/$DMG_NAME"

STAGING="$(mktemp -d)"
MOUNT_POINT=""
cleanup() {
	if [ -n "$MOUNT_POINT" ]; then
		hdiutil detach "$MOUNT_POINT" -quiet -force 2>/dev/null || true
	fi
	rm -rf "$STAGING"
}
trap cleanup EXIT

echo "==> Staging $VOLUME_NAME"
STAGE="$STAGING/$VOLUME_NAME"
mkdir -p "$STAGE"

cp -R "$APP" "$STAGE/"
cp "$CLI" "$STAGE/"
cp "$PROJECT_DIR/LICENSE" "$STAGE/LICENSE.txt"
cp "$PROJECT_DIR/THIRD-PARTY-NOTICES.md" "$STAGE/THIRD-PARTY-NOTICES.txt"

# The conventional "drag me here" affordance.
ln -s /Applications "$STAGE/Applications"

cat > "$STAGE/READ ME FIRST.txt" <<'NOTE'
FileCrypt
=========

DRAG FileCrypt.app ONTO THE Applications FOLDER TO INSTALL IT.


IMPORTANT: macOS WILL WARN YOU THE FIRST TIME
---------------------------------------------

FileCrypt is ad-hoc signed, not notarized by Apple. Notarization requires a
paid Apple Developer account, which this build does not have. So when you first
open it, macOS will say something like:

    "FileCrypt" cannot be opened because Apple cannot check it for
    malicious software.

That warning is expected. To get past it, either:

  * Right-click (or Control-click) FileCrypt.app and choose Open, then confirm.
    macOS remembers the exception for that copy; or

  * Run this in Terminal:

        xattr -d com.apple.quarantine /Applications/FileCrypt.app


IF YOU WOULD RATHER NOT TRUST A DOWNLOAD
----------------------------------------

Build it from source instead. You will get exactly what the code produces, and
a locally built app is not quarantined:

    git clone https://github.com/irshadelevision/filecrypt-app.git
    cd filecrypt-app
    ./build.sh release


A WARNING THAT MATTERS MORE THAN THE INSTALL
--------------------------------------------

There is NO PASSWORD RECOVERY. No backdoor, no escrow, no reset. If you lose
the password, the file is gone permanently. Save generated passwords somewhere
safe before you close the window.


WHAT IS ON THIS DISK
--------------------

    FileCrypt.app            the application
    fcrypt                   command-line tool (see "fcrypt --help")
    Applications             drag the app here to install
    LICENSE.txt              MIT
    THIRD-PARTY-NOTICES.txt  attribution, principally the bundled Argon2

Requires macOS 14 or newer, on Apple silicon.
NOTE

echo "==> Building the disk image"
rm -f "$DMG_PATH"
hdiutil create \
	-volname "$VOLUME_NAME" \
	-srcfolder "$STAGE" \
	-ov \
	-format UDZO \
	-fs HFS+ \
	"$DMG_PATH" >/dev/null

echo "==> Verifying"
# Mount it and confirm the contents survive the round trip.
MOUNT_POINT="$(mktemp -d)"
hdiutil attach "$DMG_PATH" -mountpoint "$MOUNT_POINT" -quiet -nobrowse -readonly

if [ ! -d "$MOUNT_POINT/FileCrypt.app" ]; then
	echo "FileCrypt.app is missing from the image" >&2
	exit 1
fi
if [ ! -x "$MOUNT_POINT/fcrypt" ]; then
	echo "fcrypt is missing from the image" >&2
	exit 1
fi

# The copy inside the image must still be a valid, signed bundle.
if ! codesign -v "$MOUNT_POINT/FileCrypt.app" 2>/dev/null; then
	echo "the app inside the image has an invalid signature" >&2
	exit 1
fi

# And the CLI must actually run from the read-only mount.
if ! "$MOUNT_POINT/fcrypt" selftest >/dev/null 2>&1; then
	echo "the fcrypt inside the image failed its self test" >&2
	exit 1
fi

hdiutil detach "$MOUNT_POINT" -quiet -force
MOUNT_POINT=""

SIZE="$(du -h "$DMG_PATH" | cut -f1)"
DIGEST="$(shasum -a 256 "$DMG_PATH" | cut -d' ' -f1)"

echo
echo "Done."
echo "  Image:  $DMG_PATH"
echo "  Size:   $SIZE"
echo "  SHA256: $DIGEST"
