# React Native, Expo, Flutter, Capacitor and Ionic

Load this file when the mobile app is built with a cross-platform framework: React Native or Expo (`react-native`, `expo` in `package.json`), Flutter (`pubspec.yaml`), Capacitor, Ionic or Cordova. These frameworks add their own layer between your code and the phone: a JavaScript or Dart bundle, native bridges, over-the-air updates and dev tooling. Load `android.md` and `ios.md` too, for each platform the app ships to. Secrets in the bundle are MOB-011 and token storage is MOB-012 in `mobile.md`.

Where to look: `app.json` / `app.config.*` and `eas.json` (Expo), `package.json`, `metro.config.*`, `pubspec.yaml`, `capacitor.config.*`, `config.xml` (Cordova), the native bridge code under `android/` and `ios/`, and the screens and routes the code map points to.

Sources: OWASP MASVS and MASTG, Expo, React Native, Flutter and Capacitor security documentation, the App Store Review Guidelines on code that changes after review.

## Updates after release
- [ ] 🔴 MFW-001 **Over-the-air updates are signed and controlled:** EAS Update code signing (or the equivalent for CodePush, Capgo, Shorebird) is on, only CI or named people can publish to the production channel, and the app rejects unsigned bundles.
- [ ] 🟡 MFW-002 **Over-the-air updates stay within store rules:** they fix and adjust; they don't add features that change what the app is, its permissions or how it uses data without going through app review.

## Release builds
- [ ] 🔴 MFW-003 **Release builds run the bundled release code:** no development server URL (Metro, Expo dev client, Capacitor `server.url`) in production builds, `__DEV__`-only code really is unreachable in release, and Flutter release builds use `--release`.
- [ ] 🟡 MFW-004 **Dev tooling is out of production:** Flipper, Reactotron, React Native debugger hooks, `expo-dev-client` and Flutter debug service extensions are development-only dependencies and aren't in the shipped app.
- [ ] 🟡 MFW-005 **Production and development builds are separate:** EAS build profiles (or flavors/schemes) give production its own API URLs, keys and app ID, so a test build can never write to production data.
- [ ] 🟢 MFW-006 **Flutter release builds are obfuscated** (`--obfuscate --split-debug-info`) and the symbol files are kept so crash reports can be read.

## Native bridges and web layers
- [ ] 🔴 MFW-007 **Native bridges check what they're given:** React Native native modules, Flutter platform channels and Capacitor/Cordova plugins validate every argument from the JavaScript/Dart side, and none offers a generic "run this", "open any file" or "call any URL" method.
- [ ] 🔴 MFW-008 **Capacitor, Ionic and Cordova apps serve the app from the bundle:** no remote `server.url` in production, `allowNavigation` lists only your own domains, and the Content Security Policy blocks injected scripts from reaching native plugins.
- [ ] 🟡 MFW-009 **`react-native-webview` (and similar) is restricted:** `originWhitelist` is your domains only, `onShouldStartLoadWithRequest` blocks unknown URLs, and `postMessage` handlers check where a message came from before acting.

## Navigation, state and packages
- [ ] 🔴 MFW-010 **Screens reached by a deep link enforce sign-in and permissions** (Expo Router, React Navigation linking, `go_router`): a link can't open an account, admin or payment screen without the same checks as normal navigation.
- [ ] 🟡 MFW-011 **Persisted app state holds no personal data in plain form:** `redux-persist`, AsyncStorage, MMKV, Hive, `shared_preferences` and similar store only what's safe on a lost phone, or encrypt it.
- [ ] 🟡 MFW-012 **Packages with native code are maintained:** React Native, Expo, Flutter and Capacitor plugins are recent, still maintained, and pass `npm audit` / `flutter pub outdated`; abandoned plugins that touch auth, payments or storage are replaced.
