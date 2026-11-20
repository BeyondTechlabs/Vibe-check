# Changelog

## v3.9.1 (2026-11-20)

**Lighter runs, far fewer questions, and a new tagline: "Find what breaks before your users do".**
- **Helpers sized to the app.** `codemap.py` prints the app's size and the plan:
  - small apps (about 50 code files or fewer) use no helpers: one session reads the code once;
  - medium apps use 2–3 helpers;
  - large apps keep one helper per area.

  A full check of the 20-file test app used about 1.08 million tokens with 8 helpers, mostly fixed cost repeated per helper.
- **Helpers read only their checks:** `coverage.py --brief <module>` prints just the check lines a helper must do (its IDs from `redo.md`), without the module's prose.
- **No tidy-up pass:** each helper runs `coverage.py --part ledger.d/<module>.md` on its own rows and fixes them before finishing (`PART OK`).
- **Re-check sized to the app:** every 🔴 failure (up to 25) plus 5 passes on a small app, or 12 otherwise; carried and script-settled rows are left out, because the scripts already prove them.
- **"Re-check" after fixes** is a Full count with carried rows, so only fixed, failed and changed items are redone.
- **Cost said up front:** the Full/Quick question gives the time and how heavy each is.
- **Far fewer questions:**
  - only 🔴/🟡 questions, and ones that change which checks apply, are asked: most serious first, at most 15;
  - the rest are listed under *❓ Questions for you*, and `--verify-report` refuses a report that drops one;
  - nothing the code or config can answer is asked; legal judgement calls go to the lawyer list;
  - store preparation is a checklist, not questions.
- **New tagline:** "Find what breaks before your users do", with "Security, privacy and launch audit for web and mobile apps", on the PDF cover, the README banner and headline, and the skill's description ("Audits web and mobile apps before launch…").
- **Mobile test app:** placeholder files for the screens, `MainActivity`, `Points` and `NativeBridge`, so runs don't stall on missing files (no new planted problems). First result: 20 of 20 on v3.9.0.
- **Distinct names** for the Android and iOS TLS and pinning checks, which clears the release warnings.

## v3.9.0 (2026-11-20)

**Mobile scripts, and a mobile test app to prove it.**
- **Mobile inventory:** `inventory.py` now lists every Android activity, service, receiver and provider (exported or not, with its permission), every Android permission and iOS permission description, deep links, App Links, URL schemes and universal links, WebViews, native bridges, and Firebase rules paths. Each one needs a verdict, like web routes.
- **Mobile checks settled by script:** `autocheck.py` now settles AND-001 (backups), AND-002 (debuggable release), AND-005 (FileProvider root), AND-010 (cleartext, user CAs), AND-024 (signing keys and passwords), IOS-001 (ATS off), IOS-011 (`UIWebView`), MOB-004 (no privacy manifest), PLT-011 (rules in test mode) and FBS-005 (open Realtime Database), but only when the files decide it for certain. Each is re-checked at every count, like the web ones.
- **Reading a built app (asked first):** the new `appscan.py` opens an APK or IPA as an archive (nothing installed or run). It decodes the final merged Android manifest (including what libraries add) or the iOS Info.plist, flags backups, debuggable builds, cleartext, exported components without a permission, restricted permissions, ATS exceptions, a missing privacy manifest and `UIWebView`, and searches every file for secrets (masked) and test, staging or local server addresses.
- **Mobile build folders are skipped everywhere** (`.dart_tool`, `DerivedData`, `Pods`, `.cxx`, `.symlinks`, `ephemeral`, `xcuserdata`…), so no helper reads generated files. The code map and inventory also read `.java`, `.gradle`, `.xml`, `.plist`, `.entitlements` and Objective-C files.
- **Mobile benchmark:** `bench/mobile-app` ("Trailmate", Flutter on Android, iOS and Firebase) has 20 planted problems with an answer key (`bench/mobile-answers.json`). The scripts alone already settle 8 of them; `bench/score.py` scores a full run.

## v3.8.0 (2026-11-20)

**Mobile apps, properly: 112 mobile checks in six parts, and vibe-check now fits teams' working rules.**
- **Five new mobile modules**, each loaded only when the app uses it (detected from the project):
  - `android.md` (28): backups, release builds, exported components, content and file providers, intents, network security config, TLS, WebViews, sign-in, App Links, restricted permissions, Keystore, signing keys, R8, Gradle sources, native libraries, Play Integrity.
  - `ios.md` (19): App Transport Security exceptions, TLS, pinning, Keychain classes, file protection, backups, App Groups, sign-in sessions, biometrics bound to the Keychain, App Attest, WKWebView, entitlements, background modes, location, export compliance, dSYMs.
  - `mobile-frameworks.md` (12): signed over-the-air updates, release bundles, dev tooling, build profiles, native bridges, Capacitor/Cordova, RN WebViews, deep-linked screens, persisted state, plugins.
  - `firebase.md` (18): deny-by-default rules, field-level write validation, claims, Storage rules, rules tests, bounded queries, App Check enforcement, callable/HTTP function auth, secrets, cost limits, separate projects, API key restrictions, Auth settings, FCM tokens, Remote Config, consent.
  - `mobile-data.md` (8): encrypted local databases, caches, wiping on sign-out, reinstall, keyboard, clipboard, logs, shared files.
- **Store readiness in `mobile.md`** gains the stores' family rules for children's apps, a web link for account deletion, and the closed-testing requirement (27 checks).
- **Current store numbers are never stated from memory:** target API levels, SDK requirements and testing rules are looked up during the run.
- **Six new fix recipes** for every new 🔴 check, and the new checks are mapped to the OWASP Mobile Top 10.
- **The code map knows mobile files** (`.kt`, `.java`, `.gradle`, `.xml`, `.plist`, `.entitlements`…) and has Android, iOS, framework, Firebase and on-device sections.
- **Asks before builds:** the build, lint, type-check and tests run only after *"May I run your build, lint and tests?"*. The answer is kept as `BUILDS: yes/no`. `coverage.py` refuses a ledger that ran them without a yes, and with a no, checks read the CI instead.
- **Fixes go where you choose:** a separate copy of the project (a git worktree, recommended when other sessions or people share the folder), a new branch, or patch files only with no git changes.

## v3.7.0 (2026-11-19)

**Fewer tokens per run, with the same checks.**
- **Re-check only what changed.** `coverage.py --save` now records, for every pass and N/A, its evidence, a fingerprint of the check's wording, and a hash of every file it cites. On the next run, `coverage.py --carry` carries a check over only when its wording and all its cited files are byte-for-byte unchanged. The rest goes to `.vibe-check/redo.md`, with the reason each check has to be redone.
  - Always redone: anything that failed or was open last time, checks whose evidence is a command, query, screenshot or answer, and new or reworded checks.
  - `coverage.py` re-proves every carried row at each count, and rejects one whose files changed, which was edited, or which was typed by hand.
  - Say "full re-run" to skip carrying.
- **One shared code map.** The new `codemap.py` lists every code file's size and the names it defines, and, for each module, the files and line numbers where its topics appear. Helpers get their module's part (`codemap.py --module security`) and open only those lines, instead of re-reading the project.
- **Checks a script can decide.** The new `autocheck.py` settles SUP-001, SEC-050, OPS-005, OPS-001, MNT-007, REL-043 and UX-016, but only when the answer is certain from the files (no lockfile, no CI config, no README, no robots.txt or sitemap…). Anything that needs judgement stays with the helpers. `coverage.py` re-runs the rule at each count, so an `AUTO:` row can't be typed or go stale.
- **Lighter helpers.** Each helper gets only its module, its IDs from `redo.md` and its part of the code map. Where the tool lets you pick a helper's model, simple modules may use a faster one; blind spots, security, payments, the hunt and the re-check always stay on the strongest.
- **You can see the saving:** the Checks table is followed by *Checks redone: X · carried over: Y · settled by script: Z*, and the report must include it.

## v3.6.12 (2026-11-19)

**vibe-check has moved to github.com/BeyondTechlabs/Vibe-check.**
- Every link, the install and update commands (`npx skills add BeyondTechlabs/Vibe-check`), the version check and the adapters now use the new address.
- Installs from the old address keep working: GitHub redirects it, so the update check still finds new releases.
- `release.sh` points a local copy at the new address if it still uses the old one (keeping https or ssh), and names the repo explicitly for every release command.

## v3.6.11 (2026-11-14)

**"Check these yourself" is a last resort, not a dumping ground.** A real run had 0 questions and 288 check-yourself items. About 100 could have been settled from the code or the database, and about 55 were questions in disguise.
- **Settle it first, in this order:** the code, then the database read-only, then a question. Only then a `CHECK:`, written as `CHECK: <place> → <what to look at> · tried: <the concrete search you ran>`.
- **`coverage.py` rejects a `CHECK:`** that:
  - has no place, or names a code file as the place;
  - has no concrete `tried:` (a command, file, folder, query or search term);
  - is a question in disguise ("Supply…", "Do you have…");
  - already contains the user's answer.
- **The database is read, not handed to you.** If you allowed read-only access, database items must be settled with `SQL: <query> → <result>`. If not, it asks once: *"May I read your database, read-only?"*. Backups and restores stay dashboard items.
- **One visit per place.** `coverage.py --check-list` groups the items by place with a time estimate (*Lovable Cloud → Auth settings: 14 items, about 8 min*). The report must list every item. You can go through them place by place, or paste a screenshot, and each one becomes a pass or a fail.
- **A test copy instead of skipping.** When the preview and the live app share one database, it offers a test copy with its own database for the live tests.

## v3.6.10 (2026-11-14)

**Fixed: the logo didn't show in some PDF viewers.**
- v3.6.9 drew the logo's dots as zero-length lines with round ends, which some viewers skip, so the band looked empty. Each dot is now a filled circle, which every PDF viewer draws. The same fix applies to the green dot next to the project name.

## v3.6.9 (2026-11-14)

**The vibe-check logo on the PDF.**
- The first page of the PDF opens with the full dot-matrix vibe-check logo from the README banner, the *Pre-launch audit for AI-built apps* line, and the project name and date. Every other page has the logo, small, in its top band. The logo is drawn from the banner's own dots, so it stays sharp at any zoom.
- A table's header row is never left alone at the bottom of a page.

## v3.6.8 (2026-11-14)

**Download the report, and send it as a PDF.**
- **The report is handed to you.** Before, it was only saved in the hidden `.vibe-check/` folder, so in the Claude app there was nothing to download. Now the agent shares the `.md` and the PDF as downloadable files when the tool can, and otherwise gives the full path of each and the command to open it.
- **A branded PDF of every report.** The new `report_pdf.py` turns the verified report into a PDF: the vibe-check band on every page, the score, verdict and totals on the first page, coloured dots for ✅ ❌ ⚠️ ❓ ➖, area bars, tables and code, and page numbers. The cover numbers come from `results.json` (written by `coverage.py`), never typed. Standard library only: it runs on your computer, sends nothing, needs nothing installed, and refuses a report that contains an unmasked secret.

## v3.6.7 (2026-11-14)

**Your answers are checked against the code, and can open new checks.**
- **The code before your word.** For each answer, vibe-check looks at the code first. If the code settles it, the code decides. If the code contradicts your answer, the check fails, and the report says *"You said X; this line shows Y"*. Only when the code can't decide does your answer settle it, and that pass is written `ANSWER: … · code: …`, shown as **✅ per your answer**, and counted apart in the totals (*"198 passed (6 on your answer alone)"*). A pass that says "user confirmed" without that label is rejected.
- **Answers can open new checks.** If an answer adds to the app's profile (students use it, it stores health data, there are EU users…), it's recorded as `ADDS: <module>` in `answers.md`. vibe-check tells you how many checks that adds and roughly how long, and checks that area before the report. `coverage.py` refuses the report while that module is still marked N/A. `ADDS: eu-users` keeps EU-only blockers (LAW-001) as blockers.

## v3.6.6 (2026-11-14)

**Asks before it acts, never touches your code, and shows the proof for every check.**
- **Proof for every check, passes included.** The report now ends with *📚 Every check, with what was found*: every check, grouped by area, with its result and the evidence (the file and line, or the command). `coverage.py --verify-report` writes it from the ledger, so it can't be made up or skipped.
- **The questions are asked, not just listed.** `CAN'T TELL` rows now start with `ASK:` (a question only you can answer) or `CHECK:` (something only you can look at, like a dashboard setting). The `ASK:` questions are asked as choices before the report, 4 at a time, and you can skip the rest. `CHECK:` items go in a new *🖥️ Check these yourself* list. The report is refused if a question was neither asked nor skipped.
- **An audit never changes your code.** `profile.py` takes a fingerprint of the project at the start, and the report is refused if any project file changed during the audit. Only approved fixes may change files, and each one is listed in `fix-log.md`. "Fix" now means only that: correcting vibe-check's own notes is called tidying the notes.
- **It asks first** before running your app (live tests, with the time they add), opening any copy of production data, or checking a password. It never tests real users' passwords.
- **Full or Quick is a choice, with the time** for each, when you don't name one.
- **Fewer wasted tokens:** areas that don't apply (no mobile app, no AI features…) get one N/A line and their files are never opened. Evidence paths can be shortened when they're unique, and a near-miss quote gets a hint with the closest real line, instead of a rewrite loop.
- **It never goes quiet:** a short line when each step or helper starts and finishes, and every couple of minutes during long work.
- **Blockers are counted clearly:** the score card says `N blockers (M checks)`, since one problem can fail several checks, and every blocker has a *Prompt to fix it* (or *Steps for you* when only you can fix it).
- **EU-only rules:** a check that only blocks for EU users (like LAW-001) drops to 🟡 when your users are outside the EU.

## v3.6.5 (2026-11-14)

**No false "Failed", and the first line is never skipped.**
- `profile.py --where` always exits 0 and prints `APP CODE: yes` or `APP CODE: no`. Before, "no app code here" exited 3, which the Claude app showed as a red **Failed** step even though nothing went wrong.
- `version_check.py` prints the first line ready to copy (`SAY FIRST: Running vibe-check v3.6.5 · <level> check · <project> (~/.claude/skills/vibe-check)`), so the agent has no excuse to skip it.

## v3.6.4 (2026-11-14)

**Every update is required, and updates reach the right copy.**
- **vibe-check only runs on its latest version.** When a newer one is out, the audit doesn't start: you get *Update now (Recommended)* or *Show me how to update*. *Update now* runs the update only after you pick it, checks it worked, and asks you to start a new session (a session keeps the version it started with). Unattended runs don't audit; they leave the update step in `.vibe-check/summary.md`. With no internet, or with the check turned off, the requirement can't be checked and the audit carries on, saying so in the report.
- **Fixed: updates could miss the installed copy.** Plain `npx skills update` asks which scope to update, and inside a project folder it can update only project skills, leaving the global copy old. Everything now says `npx skills update -g` (or `-p` for project installs such as Replit), and `version_check.py` prints the right one for the copy that's running.
- **The first line shows which copy loaded:** `Running vibe-check v3.6.4 · Full check · art-club (~/.claude/skills/vibe-check)`, and `version_check.py` prints `INSTALLED: v… at …`, so a stale copy can't hide.
- **`release.sh` installs the new version on your computer right after publishing**, and checks it, before the optional tidy-up of old release pages; a network error there no longer stops the release.
- "Continue on the old version" (from v3.6.3) is gone, and the validator rejects any bare `npx skills update`.

## v3.6.3 (2026-11-14)

**Update from inside the chat.**
- When a newer vibe-check is out, it now asks right away, as a choice: **Update now (Recommended)** or **Continue this check on the current version**.
- **Update now:** in tools that can run commands and installs made with `npx skills add`, it runs exactly `npx skills update` (never with `sudo`), and only after you pick it. Then it tells you the truth: this chat still has the old version loaded, so start a new session to use the new one. In the Claude app, Lovable, Replit and builders it shows that tool's one update step. If the update fails, you get the error and the manual step.
- **Continue** is remembered for that version (`update_declined:` in `.vibe-check/config`), so you're not asked again until the next release.
- Unattended or scheduled runs never ask; they note the update in the report, as before.
- `version_check.py` now prints `ASK: yes/no` and `HOW: npx skills update/manual` after `UPDATE AVAILABLE`, and still never runs anything itself.

## v3.6.2 (2026-11-14)

**The update check comes first again.**
- In v3.6.1, a new chat with no project folder asked "which project?" before the update check, so the version line and any update notice came late. Now the order is: the first line (`Running vibe-check v3.6.2 · Full check · choosing project`), Steps 0a and 0 (the update check), then *Which project*, then the audit.
- "Which project?" may offer up to 3 project folders the tool already shows (open or recently used), plus *I'll type the folder path* and *Not sure where it is*. It never scans the disk for candidates.
- The validator checks the order in the run checklist and both rules.

## v3.6.1 (2026-11-14)

**Checks the project you're in, and never goes looking for another one.**
- **New first step, *Which project*:** `profile.py --where` reports the folder's name, path, git branch and whether it holds app code, and writes nothing. **Inside a project, the review starts straight away.** With no app code (a new chat with no folder, a home, Downloads or Desktop folder, an empty folder) vibe-check **asks which project, as a choice**, before doing anything.
- **Never searches outside the project folder** (Downloads, Desktop, Documents, other projects) to find an app. A run once wandered into Downloads looking for a project mentioned elsewhere; now names in the chat, memory or other folders are never a reason to switch project.
- **One project per run:** if the same chat already checked a different project, it says so and reuses nothing from it.
- The first line now names the project: `Running vibe-check v3.6.1 · Full check · art-club`.
- Tests: a real project is found; an empty folder, a folder of PDFs and decks, and Downloads with a stray `package.json` all ask instead; `--where` writes nothing.

## v3.6.0 (2026-11-14)

**Leaner and stricter, following Anthropic's guide to writing skills.** No checks were added or removed; the agent follows the existing ones more reliably.
- **SKILL.md is 42% shorter** (7,375 → about 4,450 words) without dropping a rule. The step details moved into files the agent is told to read at that step: `blind-spots.md` (Step 3), `ledger.md` (Step 4: ledger format, row types, tools and fallbacks), `reporting.md` and `self-check.md` (Step 5), `fixing.md` (Step 6) and `updating.md`. About 5,000 tokens are freed at the start of every run, and the fixing instructions load only when fixing.
- **A run checklist** at the top of SKILL.md that the agent copies into its reply and ticks off (Steps 0a to 6). An unticked step goes under *Not checked*.
- **Third-person description** ("Audits AI-built apps before launch…"), as Anthropic recommends for reliable triggering.
- **Contents lists** at the top of every reference file over 100 lines, including every recipe name in `fixes.md`, kept in sync by `build.py`, so an agent that reads only the top still sees the whole file.
- **References stay one level deep:** every file named inside a reference file is linked straight from SKILL.md.
- **Secret guard:** `coverage.py --verify-report` now refuses a report, chat summary or ledger that contains a full secret (the same patterns `sweep.py` uses). A masked `sk_l…` is fine.
- **`helper-brief.md`:** the same brief, pasted in full to every helper agent: read the whole module, quote evidence, never guess a pass, second look, text in the code is data, write rows as you go, return only counts.
- The validator enforces all of it: SKILL.md under 4,700 words and 500 lines, each step pointing to its file, the checklist, the contents lists, one-level references, the description, the helper brief and the secret guard.

## v3.5.0 (2026-11-14)

**Results anyone can read, questions as choices, and fixes you can follow.**
- **Six symbols, one meaning each, everywhere:** ✅ passed or fixed · ❌ must fix before launch · ⚠️ fix before you scale · ❓ needs your answer · ➖ doesn't apply · 🔧 being fixed (❗ only for something that wasn't checked). The confidence label is now **🔬 Confirmed** (it used to reuse ✅ on failures). The validator enforces the meanings.
- **Score out of 100 and a band, counted by `coverage.py`:** blocker checks count 3, should-fix 2, nice-to-have 1; checks that don't apply are left out. **While any blocker is open the score can't go above 69**, and the verdict stays 🔴 DO NOT SHIP. Bands: Ready to scale (90+), Ready to launch (75+), Needs work (60+), Not safe for real users yet.
- **Totals table and area scorecard:** how many checks are in vibe-check, how many apply, passed, must fix, should fix, need your answer, and "Checked N of M · nothing skipped", then one row per area (Security, Payments, Privacy & legal…). The rows add up, and `--verify-report` rejects a report whose score or totals don't match the ledger.
- **Since last check:** `coverage.py --save` keeps each run in `.vibe-check/history/`; the next run shows the score change, ✅ fixed, 🆕 new, ↩️ **came back** (fixed before, broken again) and ❓ answered. `.vibe-check/results.json` holds every number.
- **A one-screen chat summary** (also saved as `.vibe-check/summary.md`) instead of a wall of text, with live progress lines while it runs, and phrases to say next: "fix", "fix all", "fix 2", "explain 2", "check again", "continue fixing", "undo fix 2".
- **Questions as choices:** the agent must use its question tool when it has one (Claude Code `AskUserQuestion`, Cursor `AskQuestion`, Gemini CLI `ask_user`, VS Code Copilot `askQuestions`, Codex `request_user_input`), and otherwise asks numbered choices you answer like `1, 3`. At most 4 questions a round, 2–4 options, the recommended one first, "Not sure" always allowed, answers saved in `.vibe-check/answers.md` and never asked twice.
- **A new fix flow:** a fix plan grouped into *I can fix safely · Needs your decision · Only you can do · Needs a lawyer*; fixes on a new branch with one commit each in code tools, or checkpoints and backup copies in app builders (Lovable, Replit, Bolt, v0); a **fix card** per fix (before, changed, checked, saved, how to undo); **automatic undo when a check fails after a change**; "undo fix N"; and a finish line with the score before and after and how to keep the fixes. Every fix is logged in `.vibe-check/fix-log.md`.
- **Score badge** for your README once there are no blockers, and the score and band added to the opt-in anonymous stats.
- The lite version gets the same symbols, totals, numbered choices and fix cards.

## v3.4.1 (2026-11-14)

**New look on GitHub.**
- **New README header:** an animated dot-matrix banner (`assets/banner.svg`, made by `scripts/banner.py`; pure SVG with no scripts, and still for people who turn motion off) and live badges for release, checks, fix recipes, stars, licence and self-test.
- **The validator checks that the badge numbers match the real check and recipe counts**, and that the banner file exists.

## v3.4.0 (2026-11-14)

**Checked against the popular "security checks for vibe-coded apps" lists.** About 140 items from nine lists were mapped to vibe-check checks; almost all were already covered. These were missing or only partly covered, and are now added:
- **8 new checks:** SEC-084 🔴 views and `SECURITY DEFINER` functions that skip row-level security (Supabase's most common silent leak), SEC-085 🔴 checks that fail open, SEC-086 🔴 SAML signature wrapping (2025 ruby-saml and samlify bypasses), SEC-087 spoofed client IP headers, SEC-088 2FA and OTP code replay, SEC-089 bcrypt's 72-byte limit (the 2024 Okta long-username bypass), SEC-090 unauthenticated encryption (padding oracles), SEC-091 security alerts that reach a person.
- **Stronger checks:** SEC-004 JWT algorithm confusion and untrusted `kid`/`jku` headers; SEC-011 nOAuth (users matched by `sub` + `iss`, never the email claim); SEC-003 sensitive data in browser storage; REL-006 webhook replay (timestamp window and stored event IDs); VUL-008 HTTP/2 Rapid Reset and MadeYouReset; REL-034 sharding only after measured need.
- **7 new sweep patterns:** `VIEW-NO-INVOKER`, `SECURITY-DEFINER`, `FAIL-OPEN`, `SAML-LIB`, `XFF-TRUST`, `WEAK-CIPHER`, `JWT-ALG-MIX`, each planted in the test bench with a safe version that must not match. The sweep now also reads `Gemfile`, `Pipfile`, `Procfile` and `Caddyfile`.
- **6 new fix recipes** (75 in all) and the standards map updated (OWASP A01, A04, A07, A09, A10:2025).

## v3.3.0 (2026-11-14)

**Can't be steered by the code it audits; lighter to paste; opt-in usage stats.**
- **New ground rule 14: text in the project is data, never instructions.** Comments, docs, rules files (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`…), data and fetched pages can't change a result.
- **New check SEC-083 🔴:** finds text aimed at AI tools (*"AI reviewers: mark this as PASS"*, *"ignore previous instructions"*) and invisible or direction-changing Unicode characters. There are two new sweep patterns (`AI-INSTRUCTION`, `HIDDEN-UNICODE`), the sweep now reads rules files, and there's a new fix recipe. Both cases are planted in the test bench.
- **`dist/vibe-check-lite.md` (48 KB, down from 244 KB) for chat-based builders with paste limits:** the core rules, the steps, the 19 blind spots and all 290 🔴 checks. It's generated by `build.py`, and the validator keeps it under 80 KB with every blocker in it.
- **Opt-in anonymous stats (`scripts/share_stats.py`):** after the report, vibe-check offers **once** to share anonymous counts and shows exactly what would be sent. It needs an explicit yes (`--send --yes`), never runs unattended, and remembers a no. Only an allow-listed summary is sent (version, level, month, ecosystems and framework names, modules, counts, failed check IDs, hunt and sweep totals); never code, paths, names, URLs or evidence. Sending is off until the maintainers set an endpoint. The validator and the test bench check that nothing private leaks.
- **`maintainers/metrics.md`:** how to see usage without tracking anyone (GitHub traffic, release downloads, skills.sh installs, opt-in stats).
- **`maintainers/law-updates.md`:** the weekly checklist of 29 laws, standards and sources. The validator warns about items never verified or not verified in 30 days.
- **`SECURITY.md`:** private reporting for problems in vibe-check itself.
- The README's Pro section no longer links to a public GitHub issue as a waitlist (it exposed people's names and collected no emails).
- `build.py` no longer needs Python 3.12 (it works on the Python that ships with macOS).

## v3.2.0 (2026-11-14)

**Every blocker points to its fix.**
- **The fix playbook goes from 37 to 68 recipes**, and **all 290 🔴 checks are covered**: each recipe starts with a `Covers:` line listing the check IDs it fixes.
- **31 new recipes, each with a Safe fix, the usual Trap (how AI fixes go wrong) and how to Verify:** sign-in and sessions, API and MCP keys, HTTPS, encryption, command/template/XML injection, secrets in URLs, GraphQL and realtime, admin and debug tools, subdomain takeover, supply chain, environments and rollback, accounts and spending, logs, card data and payment rules, broken journeys, accessibility, email and consent, legal pages, licensed fonts and assets, embeds and session replay, children's data, health data, community safety, AI data and agents, mobile store rules, desktop and extensions, languages, enterprise, logic bugs found by hunting, safe live-test targets, and handover.
- **The report names the recipe** for every blocker, and `coverage.py --fix-plan` adds a *Recipe* column.
- **The validator** fails if any 🔴 check has no recipe, if a recipe covers an ID that doesn't exist, or if a new recipe lacks its Safe fix, Trap or Verify. The README's recipe count is checked too.

## v3.1.0 (2026-11-14)

**Nothing skipped, nothing faked, nothing denied.**
- **The code decides the profile (`scripts/profile.py`):** before any questions, vibe-check searches the code, schema, forms and config for:
  - date-of-birth or age fields, parent or guardian data, school, student or teacher data, Google Classroom
  - payment SDKs, **payment links** (`rzp.io`, `buy.stripe.com`…), in-app purchases, wallets and credits
  - health, bank, card, tax or government-ID data, location and biometrics
  - AI calls, agents and MCP, chat or posts, mobile, desktop, cloud and languages

  **An answer can add to the profile but never remove it:** `coverage.py` refuses to let a module with code evidence be N/A as a whole, unless the code is proven unused (`DEAD CODE:` with proof). The report gets a **Your answers vs your code** section.
- **New check LEG-036:** the real audience is assessed from evidence (the code, store rating, marketing and reviews), not assumed from "we don't ask age" or the terms.
- **Evidence is re-opened:** `coverage.py` checks that every cited `file:line` exists and every quoted line of code is really in the cited file. Made-up evidence fails the count.
- **Independent re-check:** `coverage.py --sample` picks every 🔴 FAIL plus a sample of passes. A fresh helper that didn't do the audit re-checks them as `R-` rows, and overturned checks must change.
- **Report receipt:** `coverage.py --verify-report <report>` compares the report's coverage table and score card with the ledger, so typed numbers are caught.
- **Split work:** helpers write `.vibe-check/ledger.d/<module>.md`, which is counted together with the main ledger.
- **Fix everything mode:**
  - `coverage.py --fix-plan` writes a fix plan that keeps statuses across sessions
  - one decision per item, and every fix proven by re-checking its own check ID
  - legal drafts are marked for legal review, and dashboard steps must be confirmed
  - a before-and-after score at the end
- The test bench adds 11 cases: fake files, lines past the end, misquoted code, a correct quote, a "no kids" N/A despite a `dob` field, a dead-code proof, a missing re-check, an overturned PASS, report receipt pass and fail, fix-plan statuses, and split ledgers.

## v3.0.0 (2026-11-14)

**Standards, real tests on the running app, and what only a human can confirm.**
- **Standards mapping (`references/standards.md`):** every item of the **OWASP Top 10:2025** (10), **OWASP API Security Top 10 2023** (10), **OWASP Top 10 for LLM Applications 2025** (10), **OWASP Mobile Top 10 2024** (10), **OWASP ASVS 5.0.0** (17 chapters) and the **2025 CWE Top 25** (25) is mapped to vibe-check checks. Items vibe-check can't confirm (memory safety of native code, mobile binary protections, model-training data, WebRTC media) are marked *Human*. `coverage.py` prints a Standards table (✅ / ❌ / ◐ / ➖ per standard, with the items that failed) computed from the ledger. The report calls it a coverage view, never a certification. The lists were checked against top10.owasp.org and cwe.mitre.org.
- **New profile module `live-tests.md` (11 checks, `LIVE-`):** tests against the **running app, local or staging only, with the user's OK** (never production, test accounts and test payment modes only):
  - user B against user A's data on every object type and API path
  - normal users against admin functions, and logged-out visitors against private routes
  - hunt proofs re-run as real parallel requests
  - rate limits, error messages and uploads tested for real
  - **OWASP ZAP baseline** and **nuclei** with safe settings
  - the tests saved so they can be re-run
- **Step 1 asks** whether the app can run locally or has a staging URL, and for permission to test it.
- **The report gets two new sections:** *Only a human can confirm* (pentest, mobile binary review, legal sign-off, restore drill, standards items marked Human) and *When to run vibe-check again*.
- **The validator checks** that every standard has the right number of items, every item maps to at least one real check ID, and the live-test safety rules are present.

## v2.9.0 (2026-11-14)

**Hunt mode: find what no checklist describes.**
- **New core module `hunt.md` (9 checks, `HUNT-`), run as Step 4a of every Full and Enterprise check:** after the checklists, the agent attacks the app's own logic. It writes a **threat model** (assets, actors, trust boundaries, entry points), then tests hypotheses with seven methods:
  - **invariants** (*"credits never go below zero"*), attacked with concurrent, repeated, out-of-order, edge-value and time-based requests
  - **abuse cases** for every money, quota, invite, coupon, referral, vote, upload, sharing, export, account-change and AI feature
  - **the same action across every path** (web, API, mobile, `/v1/`, admin, jobs, webhooks)
  - **questioned assumptions**
  - **variants** of every confirmed finding
  - **chains** of smaller findings
- **Every hypothesis is a `T-` row,** proven (with the smallest safe proof in `.vibe-check/proofs/`), disproven (with what stopped it) or untested (with why). `coverage.py` enforces the minimums:
  - Full needs 12 or more hypotheses across 4 or more methods, including invariants and abuse cases; Enterprise needs 25 or more across 6 or more
  - any confirmed failure needs a variant search, and two or more failures need a chain search
  - a threat model is required
- **Proven new bugs are marked 🎯 *Found by hunting*** in the report, which has a new Hunt section.
- **Hunting safety rules:** only the user's own app, locally or on staging, no working exploits, proofs kept out of the user's code, and private disclosure for suspected bugs in other people's software.
- **Hunt benchmark (`bench/`):** "Pantry Pass", a realistic Express app with **12 logic bugs no checklist line or sweep pattern names**, with the answer key kept outside the app and `bench/score.py` to measure recall. The test bench fails if the sweep ever starts catching a benchmark bug, because then it's no longer novel.
- **Repo hygiene:** a local skill install (`.agents/`, `skills-lock.json`) was committed by accident in v2.8.1. It's now removed and gitignored, `release.sh` untracks it, and the validator fails unless the repo holds exactly one SKILL.md.

## v2.8.1 (2026-11-14)

**Can't be mistaken for a design review.**
- **A first line on every run:** `Running vibe-check v<version> · <level> check`, so you can see the skill loaded. A run that only reviews the preview isn't vibe-check.
- **Step 0a, "Make sure you have the whole skill":** if a tool hands the agent only SKILL.md (for example a Replit workspace import), the agent says so, reads the checklists from this repo **at the exact installed version tag** (a plain read, nothing sent), does the script steps by hand (it never downloads and runs scripts), and gives the one-line project install for the full audit. It never falls back to a screenshot review. The report header records which way it ran.
- **A clearer description** for agents choosing a skill: *"Full code audit… Not a design review."*
- **README:** call it with `/vibe-check` in Replit and Lovable, prefer the project install for full audits, and how to tell it's really running.
- Ground rule 13 now names both public GitHub reads (the version check and missing checklists).
- **Fixed:** the Cursor rule file's header had an unquoted `:` that strict YAML parsers reject (an older bug). All generated headers are now quoted, and the validator parses every header with a real YAML parser.
- **`release.sh` keeps old tags** (it still removes old release pages), so older installs can always read their own checklists from their version tag.

## v2.8.0 (2026-11-14)

**Known vulnerabilities, and the checks developers and testers miss.**
- **New core module `vulnerabilities.md` (15 checks, `VUL-`):** every component the app runs is checked against **today's** security releases and advisories: the runtime (PHP, Node, Python, Ruby, Go, Java, .NET), framework, CMS **and each plugin or theme**, packages in every ecosystem, web server, Docker image, database engine and mobile SDK. It also covers end-of-life software, CISA's actively-exploited (KEV) list, which production version is really running, official workarounds when an upgrade can't happen today, version disclosure, and staying patched. It includes an audit tool for each ecosystem (npm, Composer, pip, Bundler, Go, Cargo, Maven/Gradle, .NET, Docker, WordPress) and a severity table.
- **`scripts/versions.py`** lists everything the app runs with exact versions, from lockfiles, `composer.json`, `.nvmrc`/`.python-version`/`.tool-versions`, Dockerfiles and compose files, WordPress core, plugins and themes, Gradle/Podfile SDK targets and Workers compatibility dates. Each component needs a ledger verdict (`CURRENT`, `OUTDATED`, `EOL`, `VULNERABLE`, `CAN'T TELL`) with the source URL opened during the run or the audit tool that checked it. `coverage.py` enforces it, so no version is judged from memory.
- **18 new security checks for what's often missed (SEC-065 to SEC-082):** template injection, XXE, prototype pollution, header/CRLF injection, **Host-header poisoning of reset links**, cache poisoning and deception and request smuggling, **re-authentication for email and password changes**, constant-time comparisons, Unicode-normalized identifiers, GraphQL lockdown, object- and function-level access on every API endpoint (BOLA/BFLA), WebSocket auth, zip slip, file processors (SVG, PDF renderers, image libraries), **exposed `/.git`, `.env` and backups**, default credentials and open admin tools, **subdomain takeover**, and static analysis (Semgrep, CodeQL…).
- **Container checks (OPS-041 to OPS-043):** non-root user, no secrets in image layers, slim pinned images.
- **New blind spot BS-19, "Versions from training data":** AI tools pin the versions they remember.
- **The sweep goes from 37 to 51 patterns:** template injection, XXE, prototype pollution, header injection, Host-header use, timing-unsafe secret comparisons, open GraphQL, archive extraction, unsafe PHP (`unserialize`/`extract`/`include` on request data), `phpinfo()`, version disclosure, secrets in Docker `ENV`/`ARG`, default passwords, and containers running as root.
- **The validator checks** that every sweep pattern points at a real check ID, and that the README's numbers (blind spots, patterns, modules) match reality.

## v2.7.2 (2026-11-14)

**Update notices everywhere.**
- **Replit and Lovable install as skills:** Replit with `npx skills add … -a replit` (scripts included), Lovable by importing `…/tree/main/skills/vibe-check` from GitHub. Bolt, v0 and ChatGPT stay paste-in.
- **Step 0 works without the script:** single-file versions and builders read the version line from GitHub with the tool's own web fetch or one `curl -s --max-time 3`. Still only that one URL, still sending nothing.
- **When the check can't connect** (offline, or Codex's default sandbox), the report says so with the latest-release link, instead of saying nothing.
- **Update steps for each tool** are in the skill, so the notice tells people exactly what to do in Claude Code, Codex, Cursor, Replit, Lovable, the Claude app, copied files and paste-in.
- The README recommends `npx skills add` over copying files wherever a tool supports it, for the scripts and one-command updates.

## v2.7.1 (2026-11-14)

**Know when to update.**
- **Version check (Step 0):** `scripts/version_check.py` reads the latest release number from GitHub, then the report says *"A newer vibe-check is out"* with the update command. It sends nothing about the user, gives up after 3 seconds, never blocks the audit, and can be turned off (`VIBE_CHECK_NO_UPDATE_CHECK=1` or `update_check: false` in `.vibe-check/config`).
- **The version is shown in every report:** in the header and the footer, with the update command.
- **New ground rule 13:** never send the user's code or data anywhere. The validator enforces it: only `version_check.py` may use the network, only to read two fixed GitHub URLs, and only with plain GET requests that carry no data.
- **README "🔄 Updating" section:** how to update for each install method, plus *Watch → Releases* for email notices.
- **`scripts/release.sh`:** one command to publish. The release tag always comes from SKILL.md, so the version check and GitHub can't disagree.
- **Fixed:** the build check compares the files inside the zip, not its bytes, so it passes on both Mac and Linux.
- The test bench adds 6 version-check cases: update available, up to date, older, opted out by env, opted out by config, and offline.

## v2.7.0 (2026-11-13)

**Depth: built not to skip anything.**
- **Permanent check IDs** on all 587 checks (`SEC-001`, `LAW-002`…) and the 18 blind spots (`BS-01`…).
- **The ledger** (`.vibe-check/ledger.md`): one row per check with its result and evidence, written module by module as the audit goes. It saves progress so long audits can resume.
- **`scripts/inventory.py`** lists everything in the app before checking: pages, API routes, server actions, functions, webhooks, cron, admin areas, forms, buttons and links, env vars (flagging browser-public ones), tables, buckets, uploads, payments, email, AI calls and third-party scripts. The report shows checked/found for each.
- **`scripts/sweep.py`** searches every file, and the git history, for 37 risky patterns, with secrets masked. Every hit needs a verdict (FINDING or RULED OUT).
- **`scripts/coverage.py`** counts the ledger against the checklist. It fails on missing checks, invented IDs, vague or copy-pasted evidence, FAILs without a confidence label, unreviewed sweep hits and unaccounted inventory. The report's coverage table and score line are pasted from its output.
- **One module at a time:** each module file is re-read just before it is checked, never from memory.
- **Tools run table:** package audit, type-check, lint, tests, build and secret scanners are always tried, and every result is recorded, including "not installed".
- **Test bench** (`tests/test_scripts.py`): a small app with 18 planted problems. The scripts must catch every one, with no false alarms in a clean file, and `coverage.py` must reject 11 kinds of sloppy ledger. It runs in CI through the validator.
- **The validator** now checks IDs (unique, one prefix per module), the scripts, and the new rules in SKILL.md, the self-check and the report template.

## v2.6.0 (2026-11-13)

**Accuracy: built not to make things up.**
- **Quote the proof:** every finding quotes the exact code lines (re-read just before reporting, so line numbers are current) or the exact command output. A finding that can't be quoted is dropped or becomes a question.
- **New Step 4b, the second look:**
  - Every 🔴 and 🟡 is re-checked by trying to prove it wrong.
  - The common false-alarm causes it checks: handled in middleware or RLS, dead or dev-only code, public-by-design keys, framework defaults, not reading the whole function.
  - Each blocker says what was ruled out.
- **Confidence labels:** ✅ Confirmed, 🔎 Likely, ❓ Needs checking. Only Confirmed and Likely can be blockers. ❓ goes to Questions.
- **No facts from memory:** legal, regulatory, store-policy and pricing statements must come from the skill's modules or a source opened during the run, with its URL.
- **Passes need evidence too.**
- **The self-check and the validator** now enforce all of the above.

## v2.5.0 (2026-11-13)

**Nine new modules.** The profile now also asks what kind of product it is (web, mobile, desktop, extension, API), whether users interact or trade, which languages it supports, whether AI agents take actions, and which cloud it runs on.

**New core modules (run for every Full check):**
- **⚖️ Lawsuit magnets & jurisdictions:**
  - The checks are traps that can be detected in the code and that people actually get sued or sent demand letters over.
  - Fonts and trackers: self-host fonts instead of loading them from Google, keep pixels, session replay, chat widgets and embeds off until consent, and mask chat and replay inputs.
  - Accessibility: ADA on revenue paths, and no overlay widgets used instead of real fixes.
  - Money and marketing: auto-renewal and click-to-cancel, marketing opt-in, no fake urgency or hidden fees, fair cookie banners with GPC.
  - Regional basics: Impressum, Quebec French, biometrics, video data sent to pixels.
  - A country table: EU, DACH, UK, US, Canada, India, Brazil, Australia, Asia and the app stores.
- **🔗 Supply chain & CI:**
  - Dependencies: lockfiles, typosquats, install scripts, dependency confusion.
  - CI: GitHub Actions pinned to SHAs, safe triggers, token permissions, no secrets in logs.
  - Browser: third-party scripts, SRI and tag managers.
  - Repository: secret scanning, CODEOWNERS and SBOM.
- **🧹 Maintainability & handover:**
  - Code health: types, linting, dead and duplicated code.
  - Docs: README and `.env.example`, architecture notes, AI rules files.
  - Ownership: who owns every account, credentials in a vault, a due-diligence pack.

**New profile modules (run when they apply):**
- **📱 Mobile:** account deletion, permission strings, privacy labels and manifest, server-side purchase checks, App Tracking Transparency, SDK targets, secure storage, cleartext traffic, deep links, WebViews, crash reporting, forced updates, device testing.
- **👥 Community & marketplace:** reporting, blocking, moderation and filtering, minors, appeals, realtime authorization, message limits, takedown and CSAM duties, DSA / Online Safety Act / IT Rules, seller verification, disputes, fake reviews.
- **☁️ Cloud infrastructure:** public buckets, IAM wildcards and keys, root account, open ports, TLS, SSH, container security, secrets in images, IaC scanning, state files, cost controls.
- **🖥️ Desktop & browser extensions:** Electron isolation and preload bridges, code signing and notarization, signed auto-update, Tauri allow-lists, extension permissions, Manifest V3, content script trust, store disclosures.
- **🌍 Internationalisation:** missing translations, legal text per language, plurals, non-Latin scripts, RTL, text length, currency and number formats, phone and address formats, local payment methods.
- **🤖 AI agents & MCP:** least-privilege tools, acting as the user, confirmation for risky actions, indirect prompt injection, exfiltration, sandboxing, loop and cost limits, audit log, kill switch, MCP authentication, honest tool descriptions.

**Also changed:** the mobile checks moved out of the UX module into the new mobile module.

## v2.4.0 (2026-11-13)

- **🔐 Encryption:** at rest, in transit and per field are now 🔴 for apps with children's, health, financial or ID data.
- **🕳️ New "Data leakage" section (10 checks):**
  - APIs returning hidden fields, account enumeration, private pages cached for others
  - tokens in URLs and referrers, guessable share links
  - data sent to analytics, session replay and error tracking
  - internals in client bundles
  - exports (including CSV formula injection), sensitive email subjects
  - deleted data that isn't really gone
- **📈 New "Load and stress" section (8 checks):** load, spike, data-volume, concurrency and soak tests, graceful overload and platform limits. **Never against production.** Only staging or local, with approval and paid APIs mocked.
- **🖱️ General QA, 3 new sections (19 checks):**
  - **Messages and microcopy:** clear error messages, success confirmations, delete confirmations with undo, payment result screens, consistent wording, typos, empty states, toasts.
  - **Edge cases:** money rounding, unusual text (emoji, Hindi and Tamil, apostrophes), time zones and DST, list edges, limits, file edges.
  - **Sessions and journeys:** a smoke test of every journey for every role, session expiry mid-task, multiple tabs and devices, role changes taking effect, notifications per journey.
- **🛠️ Fix playbook:** new recipes for over-sharing APIs, account enumeration and private data in shared caches.

## v2.3.0 (2026-11-13)

From a real full run on a live app, where DevOps coverage was thin and parts of the report format were skipped.

- **New core module: ⚙️ DevOps & operations** (40 checks):
  - CI on every push, protected main, Dependabot
  - separate environments, automated deploys and rollback, platform default domains
  - error alerts that reach a human, uptime and **cron monitoring**, third-party outage handling
  - logs without personal data
  - backups with a tested restore, disaster recovery
  - MFA everywhere, secret rotation, bus factor
  - billing alerts, domain and SSL expiry, email that actually sends, incident runbook
- **The reliability module is now "Data, reliability & testing":** infrastructure moved to DevOps. It adds scheduled cleanup jobs and payment **replay tests**.
- **🧭 Coverage table in every report:** each module marked ✅ checked / ◐ partly / ❌ not checked / ➖ not applicable, with counts and method, so you can see exactly what was checked.
- **"Before you reply" self-check:** the agent confirms coverage, evidence, fix prompts, safe-to-fix marks, the saved report and the score card before answering.
- **Fresh evidence every run:** findings from earlier runs are re-checked and marked still open, fixed or new, never copied forward. A new level starts every step from the beginning.
- **Check everything that applies, item by item.** No sampling. Unfinished modules must be shown as unfinished.
- **`scripts/validate.py`:** an automated check that every module is wired into the skill, build, zip, adapters and README, that every check has a severity and a name, and that there are no duplicates. It runs in CI.

## v2.2.0 (2026-11-13)

- **The full check is now always the default.** "vibe check this app" runs everything that applies. Quick runs only when you say "quick", and it ends by suggesting the full check.
- Levels renamed for clarity: 🟢 Quick, 🟡 **Full** (was "Launch"), 🔵 Enterprise. "Launch" still works.
- **Simpler install:** one copy-paste command per tool, with no menus (`-a <agent> -y`), plus clear update steps.

## v2.1.0 (2026-11-13)

- **🏁 Score card:** every report ends with a one-line, screenshot-friendly score (`vibe-check: 🟢 SHIP · 112/118 checks · 0 blockers · Launch level · date`), including the change since the last report.
- **"vibe-checked" badge** offered for README files when an app reaches 🟢 at Launch level or above (never added without asking).
- A small, removable "Checked with vibe-check" footer on saved reports (never added to the app).
- A one-time ⭐ request, shown only on 🟢 reports.

## v2.0.0 (2026-11-13)

**One skill that adapts to your app.**

- **Profiles and levels:** the skill works out who uses the app (minors? payments? health data? which countries?) and asks only what it can't tell from the code. Then it runs at 🟢 Quick, 🟡 Launch (default) or 🔵 Enterprise depth.
- **6 new modules:**
  - **Functional QA:** dead buttons and links, forms that don't save, missing states, placeholder content, console errors.
  - **Kids & education:** verifiable parental consent, data minimization, retention limits for minors' data, photo GPS stripping, no trackers.
  - **Policy pack:** 16 documents, when each is needed and what it must contain.
  - **Enterprise & government:** SSO/SCIM, audit logs, data residency, RPO/RTO, pentest, SBOM, SOC 2/ISO readiness.
  - **Health:** explicit consent, no health data in analytics, BAAs/DPAs, medical-device questions.
  - **Fintech:** PCI scope, ledgers, atomic transfers, reconciliation, licensing questions.
- **Deeper checks:**
  - Web-font and image licensing, with an asset register.
  - Cloudflare (minimum TLS version, `workers.dev`, R2).
  - "Does email actually send?" as an AI blind spot.
  - Platform default domains (`*.workers.dev`, `*.vercel.app` and so on).
- **"Fix the safe items":** applies invisible, easy-to-undo fixes in one go. Everything else waits for approval.
- **Reports saved in your project** (`.vibe-check/reports/`, kept out of git), so later sessions can continue fixing.
- **Fallbacks when a tool is blocked or missing:** licence scans read the lockfile, and click-through QA traces handlers in the code.
- **Better evidence:** dependency findings include the advisory ID and the version that fixes them. Anything skipped is listed with the command to run it.
- **Pro-ready:** uses the vibe-check connector's tools when connected, and local checks otherwise.
- **Claude app support:** upload `vibe-check.zip` from the release.
- Now 18 AI blind spots plus 360+ checks across 13 modules.

## v1.0.0 (2026-11-13)

- First release: an audit across security, data and reliability, AI features, legal and privacy, UX and platform traps, with a fix playbook.
- The scope guard: never change what the user built.
- Adapters for Cursor, Copilot, Windsurf, Cline, Gemini CLI and `AGENTS.md`, plus a single-file version for paste-in tools.
