# Android apps

Load this file when the project builds an Android app: native Kotlin or Java, or the Android side of React Native, Expo, Flutter, Capacitor or Ionic (`android/`, `AndroidManifest.xml`, `build.gradle`, or `android` settings in `app.json` / `app.config.*`). Store-wide and cross-platform checks are in `mobile.md`; data kept on the device is in `mobile-data.md`.

Where to look: `AndroidManifest.xml` (and the merged manifest if a build exists), `res/xml/` (network security config, backup rules, file paths), `build.gradle(.kts)` and `proguard-rules.pro`, and the Kotlin/Java sources the code map points to. For managed Expo apps, read the `android` block and config plugins in `app.json` / `app.config.*`. Google Play's current numbers (target API level, page-size rules, testing requirements) change every year: look them up during the run from Google's own pages and cite the URL; never state them from memory.

Sources: OWASP MASVS and MASTG (Android tests), Android developer security guidance, Google Play Developer Policy Center.

## Manifest and components
- [ ] 🔴 AND-001 **Backups don't carry secrets or personal data.** `android:allowBackup` is `false`, or `android:dataExtractionRules` (Android 12+) and `android:fullBackupContent` exclude tokens, databases and files with personal data. A missing attribute means backups are **on**.
- [ ] 🔴 AND-002 **The release build is a release build:** not `debuggable`, not `testOnly`, signed with the release (upload) key, built from the release build type. Check `build.gradle` build types and the manifest.
- [ ] 🔴 AND-003 **Every activity, service, receiver and provider declares `android:exported` explicitly**, and each exported one is either meant to be public (the launcher activity, a verified app link) or protected by a permission with `protectionLevel="signature"`. Exported components that act on the user's data without a check are a 🔴.
- [ ] 🔴 AND-004 **Content providers are locked down:** not exported unless needed; `grantUriPermissions` limited to the paths that need it; read and write permissions set; queries built with selection arguments, never by joining strings (SQL injection through `query()`).
- [ ] 🔴 AND-005 **FileProvider paths are narrow:** `res/xml/*paths*.xml` shares specific folders, never the root (`path="."` or `/`), the whole app data folder, or external storage.
- [ ] 🟡 AND-006 **PendingIntents are immutable and explicit:** `FLAG_IMMUTABLE` unless mutation is required, and the wrapped intent names its target component.
- [ ] 🟡 AND-007 **Intents and broadcasts don't leak:** sensitive data goes only in explicit intents; broadcasts with personal data are sent with a permission or kept inside the app; dynamically registered receivers say whether they're exported (`RECEIVER_NOT_EXPORTED`).
- [ ] 🔴 AND-008 **No intent redirection:** the app never launches an intent taken from another app's extras (`getParcelableExtra("intent")` then `startActivity`) without checking what it targets.
- [ ] 🟢 AND-009 **Task hijacking is not possible:** no unusual `taskAffinity` or `launchMode` settings on sensitive activities that would let another app slip its screen in front of yours.

## Network
- [ ] 🔴 AND-010 **The network security config is safe in release:** no cleartext except named domains with a reason, user-installed certificate authorities aren't trusted outside `<debug-overrides>`, and no `<trust-anchors>` that accept any certificate.
- [ ] 🔴 AND-011 **TLS checking is never switched off:** no custom `TrustManager` that accepts every certificate, no `HostnameVerifier` that returns `true`, no `onReceivedSslError` that calls `handler.proceed()`, no OkHttp client built to trust all.
- [ ] 🟡 AND-012 **Certificate pinning where money or health data moves**, with backup pins and an expiry or rotation plan so a certificate change can't lock every user out.

## WebViews and links
- [ ] 🔴 AND-013 **WebViews are configured for what they load:** JavaScript only when needed; `addJavascriptInterface` only for your own bundled content, never remote pages; `setAllowFileAccess(false)`, `setAllowFileAccessFromFileURLs(false)` and `setAllowUniversalAccessFromFileURLs(false)` unless a feature needs them; URLs checked in `shouldOverrideUrlLoading`.
- [ ] 🔴 AND-014 **Sign-in never happens in a WebView:** OAuth and other sign-in flows use Custom Tabs or the system browser with PKCE, and auth codes return through verified App Links, not a custom scheme another app could also register.
- [ ] 🟡 AND-015 **App Links are verified:** intent filters for your domain use `android:autoVerify="true"`, and the matching `/.well-known/assetlinks.json` lists the release signing certificate fingerprint (including Play App Signing's).

## Permissions and Play policy
- [ ] 🔴 AND-016 **Restricted permissions are justified:** `QUERY_ALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, SMS and call log, `ACCESS_BACKGROUND_LOCATION`, accessibility services and exact alarms are only declared when the app's core feature needs them and Play's policy allows it (Play rejects or removes apps otherwise).
- [ ] 🟡 AND-017 **Foreground services declare their type** and the matching permission, and run only for work the user started and can see.
- [ ] 🟡 AND-018 **Permissions are the minimum:** every `uses-permission` in the merged manifest (including ones added by libraries) is needed; unneeded ones are removed with `tools:node="remove"`.
- [ ] 🟡 AND-019 **Location is as coarse as the feature allows:** approximate location unless precision is needed; background location only with a clear in-app reason.

## Storage and keys
- [ ] 🔴 AND-020 **Secrets and keys live in the Android Keystore:** encryption keys are generated in the Keystore (hardware-backed where available), never hard-coded or stored next to the data they protect; tokens aren't in plain `SharedPreferences`.
- [ ] 🔴 AND-021 **No world-readable files or shared storage for private data:** no `MODE_WORLD_READABLE`/`WRITEABLE`; personal data stays in app-private storage, not `Download/`, `DCIM/` or other shared folders.
- [ ] 🟡 AND-022 **Local SQL is parameterised:** `rawQuery`, `execSQL` and Room `@RawQuery` use bound arguments, never strings built from input.

## Build, release and supply chain
- [ ] 🟡 AND-023 **R8 shrinking and obfuscation are on for release** (`isMinifyEnabled = true`) with keep rules that don't keep everything, and the mapping file is uploaded to the crash reporter so stack traces stay readable.
- [ ] 🔴 AND-024 **Signing keys and passwords are not in the repo:** no `.jks`/`.keystore` files committed, no store or key passwords in `build.gradle` or `gradle.properties`; the upload key is separate from the app signing key (Play App Signing).
- [ ] 🟡 AND-025 **Gradle dependencies come from trusted repositories:** no `jcenter()` or unknown Maven URLs, the Gradle wrapper is the official one, and versions are pinned (no `+` versions).
- [ ] 🟡 AND-026 **Native libraries meet Play's current rules:** bundled `.so` files come from known sources, are up to date, and meet Play's current requirements for native code (such as page-size support). Look the requirement up.
- [ ] 🟡 AND-027 **High-value actions can check the device and app are genuine** (Play Integrity API verified on the server) where abuse would cost money or harm users: payments, rewards, sign-up bonuses, voting.
- [ ] 🟢 AND-028 **Tapjacking is blocked on sensitive buttons:** `filterTouchesWhenObscured` (or a check of `FLAG_WINDOW_IS_OBSCURED`) on confirm, pay and permission screens.
