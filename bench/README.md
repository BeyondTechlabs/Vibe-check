# Hunt benchmark

`hunt-app/` is a small, realistic Express app ("Pantry Pass") with **12 logic bugs that no vibe-check checklist line or sweep pattern names directly**: races, stacking coupons, negative totals, skipped payment states, an old endpoint missing an owner check, a self-chosen role, quota resets, referral farming, webhook retries, an open redirect that leaks a session token, and an unlimited AI bill. They're the kind of bug only **hunt mode** (attacking the app's own logic) finds. The answer key, `hunt-answers.json`, stays outside the app folder.

## Run it
1. Copy the app somewhere the agent can't see the answers:
   ```bash
   cp -R bench/hunt-app /tmp/pantry-pass && cd /tmp/pantry-pass && git init -q && git add -A && git commit -qm init
   ```
2. Open `/tmp/pantry-pass` in your AI tool (with vibe-check installed) and say **"vibe check this app"** (a Full check).
3. Score the ledger it wrote:
   ```bash
   python3 bench/score.py /tmp/pantry-pass/.vibe-check/ledger.md
   ```

Record the result in the table below with the vibe-check version, tool and model, so changes to hunt mode can be measured. Don't tune the skill to these exact bugs: add new cases instead.

| Date | vibe-check | Tool and model | Found |
|---|---|---|---|
| | | | |

# Mobile benchmark

`mobile-app/` is a small Flutter app ("Trailmate") for Android and iOS on Firebase, with **20 planted mobile problems** across the Android, iOS, framework, Firebase and on-device checks: backups, a debuggable release, cleartext, an exported admin screen, a FileProvider sharing everything, a trust-all TrustManager, a WebView bridge, signing passwords, tokens in SharedPreferences and UserDefaults, a token in the log, ATS off, no privacy manifest, open Firestore and Storage rules, a callable function with no auth check, a staff check on a client-writable field, an unguarded deep link to an admin screen, sign-in inside a WebView, and a release build pointing at a developer machine.

## Run it
1. Copy the app somewhere the agent can't see the answers, as a git repo:
   ```bash
   cp -R bench/mobile-app /tmp/trailmate && cd /tmp/trailmate && git init -q && git add -A && git commit -qm init
   ```
2. Open `/tmp/trailmate` in your AI tool and say **"vibe check this app"** (a Full check). Say no to builds: it's not a buildable project.
3. Score it:
   ```bash
   python3 bench/score.py /tmp/trailmate/.vibe-check/ledger.md bench/mobile-answers.json
   ```

| Date | vibe-check | Tool and model | Found |
|---|---|---|---|
| 2026-11-20 | 3.9.0 | Claude desktop app (Code), Opus 5.5, medium effort | 20 / 20, checked against the report text (all 20 are findings in the blockers; 8 settled by script) |
| 2026-11-21 | 5.0.0 | Claude desktop app (Code), Opus 5.5, medium effort | 20 / 20 by `score.py` (all 20 in the 16 blockers; 12 settled by script). A re-check on the 2026-11-20 folder, not a fresh copy: about 218k tokens in one conversation with no helpers, against about 1.08M with 8 helpers before |
