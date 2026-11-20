# Data on the device

Load this file for every mobile app (native or cross-platform). A phone gets lost, shared, backed up and handed in for repair, so what the app leaves on it matters as much as what the server protects. Token storage is MOB-012 and the app-switcher snapshot is MOB-017 in `mobile.md`; Android and iOS details are in `android.md` and `ios.md`.

Where to look: local database setup (SQLite, Room, Core Data, SwiftData, Realm, Hive, Isar, MMKV, WatermelonDB), HTTP and image cache settings, sign-out and account-deletion code, text fields for passwords, codes and card numbers, logging calls, and file export or share code.

Sources: OWASP MASVS-STORAGE and MASVS-PRIVACY, Android and Apple platform security documentation.

## Stored data
- [ ] 🔴 MDV-001 **Local databases with personal, health or money data are encrypted** (SQLCipher, encrypted Realm or MMKV, or the platform's file protection with keys in the Keychain/Keystore), or that data isn't kept on the device at all.
- [ ] 🟡 MDV-002 **Caches don't keep sensitive responses:** API responses with personal data aren't stored in the HTTP or image cache (`Cache-Control: no-store` honoured, `URLCache` and OkHttp caches configured), and cached files are cleared when they're no longer needed.
- [ ] 🔴 MDV-003 **Sign-out and account deletion wipe the device:** tokens, Keychain/Keystore items, local databases, caches and downloaded files are removed, so the next person to use the phone sees nothing.
- [ ] 🟡 MDV-004 **A reinstall doesn't bring back an old session:** iOS Keychain items survive uninstall, so the app clears leftover credentials on first launch after a fresh install.

## Input, clipboard and logs
- [ ] 🟡 MDV-005 **Sensitive fields don't leak through the keyboard:** passwords use secure entry, one-time codes use the one-time-code content type, and autocorrect and suggestions are off for card numbers, codes and other secrets so the keyboard doesn't learn them.
- [ ] 🟡 MDV-006 **Sensitive values don't sit on the clipboard:** they can't be copied, or are marked sensitive (Android 13+) and expire (iOS `UIPasteboard` expiry, local-only).
- [ ] 🔴 MDV-007 **Logs and crash reports carry no tokens or personal data:** no `print`, `console.log`, `Log.d`, `NSLog` or `os_log` of tokens, passwords, emails, health or money details in release builds; crash reporter keys and breadcrumbs are scrubbed.
- [ ] 🟡 MDV-008 **Shared and exported files don't linger:** files created for sharing, printing or export are written to temporary storage and deleted afterwards, and never to shared folders other apps can read.
