# Firebase and mobile backends

Load this file when the app uses Firebase (`firebase.json`, `firestore.rules`, `storage.rules`, `database.rules.json`, `google-services.json`, `GoogleService-Info.plist`, or Firebase SDKs in the code). Most mobile apps keep their server side here, so this is where one user reaching another user's data usually goes wrong. The basics (rules not in test mode, ownership checks, App Check on, Cloud Functions checking auth, budget alerts) are PLT-011 to PLT-015 in `platforms.md`; this file goes deeper.

Where to look: the rules files, `firebase.json`, `firestore.indexes.json`, the `functions/` folder, the Firebase calls in the app the code map points to, and any rules tests. Console-only settings (App Check enforcement, Auth settings, API key restrictions) can be read with the Firebase CLI or `gcloud` if the user allows it; otherwise they're `CHECK:` items with the exact console path.

Sources: Firebase Security Rules and App Check documentation, Google Cloud API key guidance, OWASP MASVS.

## Security rules
- [ ] 🔴 FBS-001 **Rules deny by default:** every collection and storage path is matched explicitly; there's no broad recursive wildcard (`match /{document=**}`) that allows reads or writes, and anything not matched is refused.
- [ ] 🔴 FBS-002 **Writes are validated field by field:** rules limit which keys a client may write (`request.resource.data.keys().hasOnly([...])`), check types and sizes, and keep fixed fields (owner ID, creation time, price, balance) from being changed by the client.
- [ ] 🔴 FBS-003 **Admin and role checks come from custom claims set on the server** (`request.auth.token.admin`), never from a field in a document the user can write.
- [ ] 🔴 FBS-004 **Storage rules tie paths to the signed-in user** (`/users/{uid}/...` matching `request.auth.uid`), limit file size and content type, and allow no public writes.
- [ ] 🟡 FBS-005 **Realtime Database rules** don't set `.read` or `.write` to `true` at any level above user data, and use `.validate` for the shape of writes.
- [ ] 🟡 FBS-006 **Rules have tests that run:** emulator tests (`@firebase/rules-unit-testing` or similar) prove that other users, signed-out users and wrong fields are refused, and they run in CI or before each deploy.
- [ ] 🟡 FBS-007 **Queries are bounded:** reads use `limit` and pagination, listeners are detached when screens close, and the rules check `request.query.limit` where a large read would cost money or expose data.

## Functions and App Check
- [ ] 🔴 FBS-008 **App Check is enforced, not just monitored,** for Firestore, Storage and callable functions (`enforceAppCheck: true`), once the app's own traffic passes it.
- [ ] 🔴 FBS-009 **Every callable and HTTP function checks who's calling:** callable functions use `request.auth` and refuse when it's missing; HTTP functions verify the Firebase ID token; functions acting for a user re-check that the user may do it, because the Admin SDK skips the rules.
- [ ] 🟡 FBS-010 **Function secrets are in Secret Manager** (`defineSecret` or similar), not in code, `.env` files in the repo, or the deprecated runtime config; the functions' service account has only the roles it needs.
- [ ] 🟡 FBS-011 **Functions can't run up an unlimited bill:** `maxInstances` (or concurrency limits), timeouts, and rate limits on public endpoints, so one abusive client can't scale costs without limit.

## Project and keys
- [ ] 🔴 FBS-012 **Production has its own Firebase project:** debug and test builds point to a separate project, so testing never touches real users' data.
- [ ] 🟡 FBS-013 **Google API keys shipped in the app are restricted** to the app (Android package name and signing certificate SHA-1, iOS bundle ID) and to the APIs it uses. The key isn't secret, but an unrestricted one can be used by anyone, on your bill.
- [ ] 🟡 FBS-014 **Auth settings are tightened:** email enumeration protection on, unused sign-in providers off, the authorized domains list has no leftover test or `localhost` entries in production, and password rules fit the app.
- [ ] 🟡 FBS-015 **Push tokens belong to the signed-in user:** FCM tokens are stored per user under rules only that user can write, removed at sign-out and on account deletion, and messages are sent only from the server.
- [ ] 🟡 FBS-016 **Remote Config holds no secrets and makes no security decisions:** values reach every device, so feature flags must not be the only thing stopping access to paid or admin features.
- [ ] 🟡 FBS-017 **Analytics and Crashlytics respect consent and age:** collection is off until consent where the law requires it, off for minors where required (see `kids-education.md`), and custom events and keys carry no personal data.
- [ ] 🟢 FBS-018 **No dependence on Firebase Dynamic Links,** which Google has shut down: links use App Links / universal links or another provider. Check Firebase's notice for the current status.
