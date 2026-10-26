#!/usr/bin/env bash
# Builds build/CursorUsageBar.app. With --install, copies it to ~/Applications and launches it.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/CursorUsageBar.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

swiftc -O -parse-as-library -swift-version 5 \
  -target "$(uname -m)-apple-macos14.0" \
  Sources/CursorUsageBar.swift \
  -o "$APP/Contents/MacOS/CursorUsageBar"
cp Info.plist "$APP/Contents/Info.plist"
codesign --force --sign - "$APP"
echo "Built $APP"

if [[ "${1:-}" == "--install" ]]; then
  DEST="$HOME/Applications/CursorUsageBar.app"
  pkill -x CursorUsageBar || true
  mkdir -p "$HOME/Applications"
  rm -rf "$DEST"
  cp -R "$APP" "$DEST"
  open "$DEST"
  echo "Installed and launched $DEST"
fi
