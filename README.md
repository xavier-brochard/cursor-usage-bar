# Cursor Usage Bar

A tiny macOS menu bar app that shows your Cursor monthly usage at a glance, the same number as the "Your monthly usage" card on [cursor.com/dashboard/usage](https://cursor.com/dashboard/usage):

```
412.50/2000
```

Click it for details:

- `$412.50 of $2,000 (21%)`
- `$1,587.50 left · resets Nov 1`
- Refresh Now (⌘R), Open Usage Dashboard, Launch at Login, Quit

It refreshes every 5 minutes and after your Mac wakes up. A `⚠︎` prefix appears at 90% usage or when the last refresh failed.

Single Swift file, no dependencies, no Dock icon.

## Requirements

- macOS 14 or later
- Xcode or the Xcode Command Line Tools (`swiftc`)
- Cursor.app installed and signed in

## Build and install

```bash
git clone https://github.com/xavier-brochard/cursor-usage-bar.git
cd cursor-usage-bar
./build.sh --install
```

This builds `build/CursorUsageBar.app`, copies it to `~/Applications`, and launches it. Run `./build.sh` without `--install` to only build.

On first launch macOS asks whether **CursorUsageBar** may use **"Cursor Safe Storage"** in your keychain. Click **Always Allow**. Because the app is ad-hoc signed, the prompt comes back after each rebuild.

To start it automatically, enable **Launch at Login** in its menu.

## How it works

1. **Auth.** It reuses Cursor.app's login, so there's nothing to configure:
   - It reads `cursorAuth/accessToken` from Cursor's local database (`~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`), read-only.
   - Cursor encrypts that token with Electron safeStorage. The app decrypts it with the key derived from the "Cursor Safe Storage" Keychain item.
   - The token is re-read on every refresh, so it follows Cursor's own token rotation. The app never writes to Cursor's data and never refreshes tokens itself.
2. **Data.** It calls `GET https://cursor.com/api/usage-summary` with the `WorkosCursorSessionToken` cookie and shows `individualUsage.overall` for team and enterprise plans, or `onDemand` / `plan` for others. Your token is only sent to cursor.com.

**Fallback.** If reading Cursor's login fails, copy the `WorkosCursorSessionToken` cookie value from your browser's DevTools on cursor.com and choose **Use Session Cookie from Clipboard**. It's stored in your Keychain and used whenever Cursor's own login doesn't work. Paste a new one when it expires.

## Command line

```bash
# Print current usage and exit
~/Applications/CursorUsageBar.app/Contents/MacOS/CursorUsageBar --print

# Dump raw API responses to debug API changes (may include account details; don't share publicly)
~/Applications/CursorUsageBar.app/Contents/MacOS/CursorUsageBar --probe
```

Set `CURSOR_DB_PATH` to point at a different `state.vscdb`.

## Uninstall

Turn off **Launch at Login**, quit the app, then:

```bash
rm -rf ~/Applications/CursorUsageBar.app
```

## Caveat

Cursor has no official usage API for individual members. This app relies on the same unofficial endpoints the dashboard uses, and on Cursor's local token storage format. Either can change without notice. If the menu bar shows `⚠︎`, run `--probe` to see what changed.

## License

MIT
