# iOS apps

Load this file when the project builds an iOS app: Swift or Objective-C, or the iOS side of React Native, Expo, Flutter, Capacitor or Ionic (`ios/`, `*.xcodeproj`, `Info.plist`, `Podfile`, `Package.swift`, or `ios` settings in `app.json` / `app.config.*`). Cross-platform store checks, including permission descriptions (MOB-002), the privacy manifest (MOB-004), the tracking prompt (MOB-006), Sign in with Apple (MOB-007), SDK requirements (MOB-008), App Transport Security basics (MOB-013), universal links (MOB-014) and the app-switcher snapshot (MOB-017), are in `mobile.md`; data kept on the device is in `mobile-data.md`. This file goes deeper on what's specific to iOS.

Where to look: `Info.plist`, `*.entitlements`, `PrivacyInfo.xcprivacy`, the Xcode project's build settings and schemes, and the Swift/Objective-C sources the code map points to. For managed Expo apps, read the `ios` block (`infoPlist`, `entitlements`) and config plugins in `app.json` / `app.config.*`. Apple's current requirements change: look them up during the run from Apple's own pages and cite the URL; never state them from memory.

Sources: OWASP MASVS and MASTG (iOS tests), Apple Platform Security guide, Apple developer documentation, App Store Review Guidelines.

## Network
- [ ] 🔴 IOS-001 **App Transport Security exceptions are narrow:** only per-domain exceptions under `NSExceptionDomains`, each with a reason; no `NSAllowsArbitraryLoadsInWebContent` or `NSAllowsArbitraryLoadsForMedia` unless a feature needs it; the minimum TLS version isn't lowered.
- [ ] 🔴 IOS-002 **TLS checking is never switched off:** no `URLSession` delegate that accepts any server trust, no Alamofire `DisabledTrustEvaluator` (or similar) in release code, no "allow invalid certificates" flags.
- [ ] 🟡 IOS-003 **Certificate pinning where money or health data moves**, with backup pins and a rotation plan, so a certificate change can't lock every user out.

## Keys, files and backups
- [ ] 🔴 IOS-004 **Secrets live in the Keychain with the right accessibility:** a `...ThisDeviceOnly` or `AfterFirstUnlock` class suited to the use, never the deprecated `kSecAttrAccessibleAlways`; no tokens or keys in `UserDefaults`, plists or files in the app container.
- [ ] 🟡 IOS-005 **Files with personal data use complete data protection** (`.completeFileProtection` / `NSFileProtectionComplete`, or the app-wide default set in the entitlements) so they're unreadable while the device is locked.
- [ ] 🟡 IOS-006 **Sensitive files are kept out of device and iCloud backups** (`isExcludedFromBackup`, or in `Caches` when they can be rebuilt).
- [ ] 🟡 IOS-007 **App Groups and extensions share only what they need:** widgets, share and notification extensions read a minimal shared container; keychain access groups are as narrow as possible.

## Sign-in and identity
- [ ] 🔴 IOS-008 **Sign-in never happens in an embedded web view:** OAuth and other sign-in flows use `ASWebAuthenticationSession` (or the system browser) with PKCE, never a `WKWebView` that could read the user's password.
- [ ] 🟡 IOS-009 **Face ID / Touch ID protects a Keychain item,** using `SecAccessControl` with a biometry flag, not a bare `LAContext.evaluatePolicy` true/false that a patched app could skip.
- [ ] 🟢 IOS-010 **App Attest or DeviceCheck protects high-value APIs** (rewards, sign-up bonuses, voting) when Firebase App Check isn't used, with the assertion verified on the server.

## Web content
- [ ] 🔴 IOS-011 **WKWebView only:** no `UIWebView` anywhere, including inside third-party SDKs (Apple rejects apps that still contain it).
- [ ] 🟡 IOS-012 **WKWebView bridges are safe:** `WKScriptMessageHandler` checks the message's origin and content; no file-URL universal access; only your own or allow-listed sites are loaded where native features are exposed.

## Capabilities and configuration
- [ ] 🟡 IOS-013 **Entitlements are the minimum:** associated domains match the `apple-app-site-association` file; push, iCloud, HealthKit, App Groups and others appear only when used; `aps-environment` is `production` in release builds.
- [ ] 🟡 IOS-014 **Background modes match real features:** only the `UIBackgroundModes` the app uses (audio, location, fetch, processing). App Review rejects declared modes the app doesn't need.
- [ ] 🟡 IOS-015 **Location is as limited as the feature allows:** "when in use" unless "always" is essential and explained; precise location only where needed.
- [ ] 🟡 IOS-016 **Export compliance is declared correctly:** `ITSAppUsesNonExemptEncryption` in `Info.plist` matches what the app's encryption actually is.
- [ ] 🟡 IOS-017 **Crash symbols are uploaded:** release builds upload dSYMs to the crash reporter (an upload step in the build or CI), so crash reports can be read.
- [ ] 🟢 IOS-018 **Third-party keyboards are blocked for sensitive input** where the app handles passwords, card numbers or health data (`shouldAllowExtensionPointIdentifier` for keyboards).
- [ ] 🟢 IOS-019 **Jailbreak detection, if used, is one signal among several,** never the only thing protecting money or data, and doesn't lock out honest users without a way forward.
