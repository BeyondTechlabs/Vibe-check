# The ledger: format, row types and tools

Read this at Step 4, before the first ledger row. Every result goes in the ledger; `coverage.py` counts it.

## The ledger

**The ledger is the audit's memory.** Create `.vibe-check/ledger.md` at the start:

```markdown
# vibe-check ledger
Level: Full
Date: YYYY-MM-DD

| ID | Result | Evidence / reason |
|---|---|---|
| SEC-001 | PASS | src/lib/auth.ts:4 uses Clerk; no custom password code (grep "bcrypt\|jwt.sign": 0 hits) |
| SEC-030 | FAIL 🔎 Likely | app/notes/[id]/page.tsx:41 renders note.body with dangerouslySetInnerHTML |
| SEC-047 | CAN'T TELL | ASK: invite codes come from an external service. Are they single-use and do they expire? |
| OPS-031 | CAN'T TELL | CHECK: Cloudflare → My Profile → Authentication → 2FA is on for every admin · tried: `rg -i "2fa|mfa" .github/ docs/` found nothing; it's an account setting |
| PLT-011..PLT-015 | N/A | not on Firebase |
| HLT-* | N/A | no health, medical or fitness data |
| INV-api_routes | 47/47 | every route traced to its auth check |
| H-001..H-003 | RULED OUT | Supabase anon key: public by design, RLS on (SEC-017 PASS) |
| H-004 | FINDING SEC-022 | live Stripe key in src/lib/stripe.ts:3 |
| V-002 | OUTDATED | PHP 8.3.35, security release 8.3.36 is out: https://www.php.net/releases/ (opened today) |
| V-005..V-031 | CURRENT | npm audit --omit=dev: 0 vulnerabilities |
```

- **Results:** `PASS`, `FAIL 🔬 Confirmed` / `FAIL 🔎 Likely`, `N/A`, `CAN'T TELL`. Every row needs its own evidence or reason. Copy-pasted evidence is rejected.
- **`CAN'T TELL` says which kind it is,** first thing in the reason: `ASK:` when a tap or a short answer from the user settles it (a business rule, whether an old deployment still runs), or `CHECK:` when only the user can look. `ASK:` items are asked before the report when they matter (🔴/🟡, up to 15; see `reporting.md`), and listed in it otherwise; never write `ASK:` for what the code or config can answer, or for a legal judgement call (that goes on the lawyer list); `CHECK:` items become the *Check these yourself* list.
- **Settle it yourself first; `CHECK:` is the last resort.** Before writing either, work through this order, and stop at the first that settles it:
  1. **The code:** search and read it (`rg`, the files, the migrations, the config). If the code shows it, it's PASS or FAIL. "It's a lot of files" is never a reason for `CHECK:`.
  2. **The database, read-only:** policies, grants, functions, views, cron jobs, tables (audit logs, roles), storage buckets. With access, write `SQL: <query> → <result>` as evidence. Without it, ask once, as a choice: *"May I read your database, read-only? It settles N checks."* and write `DATABASE: yes` or `DATABASE: no` in `.vibe-check/answers.md`. Backups and restores are dashboard items, not SQL.
  2b. **The live accounts, read-only:** if `live.py --detect` shows the tool signed in, ask once and read it (`live-accounts.md`); copy its result as `LIVE: <id> → <summary>`.
  3. **A question:** anything the user knows from memory (do you have a written plan, a policy, a contract, a process; who does X) is `ASK:` and is asked as a choice, never `CHECK:`.
  4. **Only then `CHECK:`,** for a place outside the code and database that only the user can open, written exactly as `CHECK: <place> → <what to look at> · tried: <the concrete search you ran first>`, for example `CHECK: Lovable Cloud → Users → Auth settings → CAPTCHA is on · tried: \`rg -i captcha src/ supabase/\` found nothing`. The running app counts as a place (`CHECK: the running app → …`) when live tests weren't allowed.
  
  `coverage.py` rejects a `CHECK:` with no place, a code file as the place, no concrete `tried:`, a question in disguise, an answer already inside it, or a database item when you have (or could ask for) read-only access. `coverage.py --check-list` prints the items grouped by place for the report.
- **A screenshot settles a `CHECK:`.** When the user pastes one, read it and write `PASS` or `FAIL` with `screenshot: <what it shows>, pasted <date>`.
- **A pass that rests on the user's answer is written as one:** `| SEC-047 | PASS | ANSWER: single-use, expire in 7 days · code: codes come from an outside service, nothing here decides it |`. The `code:` part says what you looked at first and why the code can't settle it. The report shows it as **✅ per your answer**, and the totals count it apart. A pass with "user confirmed" and no `ANSWER:` is rejected. If the code can settle it, the code decides, never the answer.
- **An answer that adds to the profile gets an `ADDS:` line in `.vibe-check/answers.md`:** `ADDS: kids-education · Q2: students use it`, `ADDS: fintech`, `ADDS: health`, `ADDS: eu-users`. That module then can't stay `N/A`: check its items before the report. `eu-users` keeps EU-only blockers (LAW-001) as blockers.
- **Evidence that's easy to verify:** cite `path:line` (a shortened path is fine when it matches only one file) and quote code as it appears. When `coverage.py` rejects a row it says why and shows the closest real line: correct that row once and move on. Don't rewrite rows that passed. **This is tidying the audit notes, never "fixing"**: that word is only for changing the user's code after they approve.
- **Blockers that depend on the country:** a 🔴 check marked *(blocker for EU users)* that fails in an app with no EU or EEA users is recorded as usual, with `outside the EU` in the evidence; it then counts as ⚠️ should-fix.
- **Modules that don't apply:** for a profile module the profile rules out (no mobile app, no AI, no payments…), don't open its file. Write one row, `MOB-* | N/A | profile: no mobile app (profile.json)`, and move on.
- **Ranges and `*` are for N/A only** (a platform section you don't use, a profile module that doesn't apply). Core modules are never N/A as a whole.
- **`RUN:` rows** copy a result from `.vibe-check/runtime/summary.md` exactly (runtime tests of the local or approved staging app, `live-tests.md`), checked the same way against `RUNTIME: yes`.
- **`LIVE:` rows** copy a result from `.vibe-check/live/summary.md` exactly; `coverage.py` checks it against the saved result, its check, its verdict, its age and the user's `LIVE: <provider>: yes`.
- **Rows written by scripts, never by hand:** `AUTO:` rows in `ledger.d/01-auto.md` come from `autocheck.py` (checks a script can decide for certain: no lockfile, no CI config, no README…); `CARRIED from <date> run (<run>):` rows in `ledger.d/00-carried.md` come from `coverage.py --carry` (a pass or N/A whose check wording and every cited file are byte-for-byte unchanged since the last saved run). `coverage.py` re-runs the rule or re-hashes the files at every count, and rejects a row that no longer holds or was typed by hand. To redo a carried check, delete its row and check it again.
- **`INV-<category>` rows:** checked/found for every inventory category that has items. **`H-` rows:** a verdict for every sweep hit. **`V-` rows:** a verdict for every component in `.vibe-check/versions.md`, with its source.
- **Split the work when you can.** In tools with helper agents (subagents), give each module, or group of small modules, to its own fresh helper with the inventory, sweep, versions and profile files. Each helper writes its rows to `.vibe-check/ledger.d/<module>.md`; `coverage.py` reads them together with the main ledger. Without helpers, work one module at a time and resume with `coverage.py --remaining`.
- **Evidence is checked against the files.** Every `file:line` you cite must exist, and code you quote in backticks must appear in the cited file exactly: `coverage.py` re-opens the files and rejects anything that doesn't match. Re-read before you quote.
- **One module at a time.** Re-open the module file and read it **just before** checking it (never from memory), check every item, and **write its rows to the ledger immediately.** That saves progress: on a big app, if the conversation gets long, run `python3 <skill-folder>/scripts/coverage.py --remaining` and continue from what's left instead of getting shallower.
- **Tools run:** add a `## Tools run` table to the ledger: every tool you ran or tried (`npm audit`, type-check, lint, tests, build, secret scanner, Lighthouse…), the exact command, and the result, including *"not installed"* or *"failed: <error>"*.

## Tools and fallbacks

**Ask once before running the project's build, lint, type-check or tests** (they take time, write build output, and some teams don't let agents run them): *"May I run your build, lint and tests? It adds about N minutes"* · *Yes (Recommended)* · *No, read the code only*. Write `BUILDS: yes` or `BUILDS: no` in `.vibe-check/answers.md` and reuse it on later runs. `coverage.py` refuses a ledger whose *Tools run* table shows a build, lint, type-check or test command without `BUILDS: yes`. With `BUILDS: no`, list those tools as `not run: you said no builds`, and checks that need them read the CI's latest run or config instead, or become `CHECK: your CI → latest run → …`.

**Then try the project's own tools** and record each in the ledger's *Tools run* table: the package audit (`npm audit` / `pnpm audit` / `pip-audit`, read-only, no question needed) and, with `BUILDS: yes`, type-check (`tsc --noEmit` or the framework's check), lint, the test suite, and the build. Then use what's available: gitleaks or trufflehog, `npx license-checker`, Lighthouse, axe, Playwright, and `curl -I` against live URLs. **If a tool is missing or blocked, don't skip the check:** use the fallback, and say which method you used.

| Check | Fallback |
|---|---|
| License scan | Read the `license` field of each dependency from the lockfile or `node_modules/*/package.json` |
| Secret scan | The grep patterns in blind spot #3, over files and `git log -p` |
| Click-through QA | Static review: every `onClick`, `<a href>`, form `action` and route traced to a handler that exists (see `functional-qa.md`) |
| Lighthouse / axe | Manual review of the main pages against `launch-ux.md` |
| Dashboard-only settings (backups, MFA, billing alerts, branch protection, uptime monitors) | Check config files and `gh` / platform CLIs if logged in; otherwise `CAN'T TELL` with `CHECK:` and exactly where to look |
| Build | List it under "Not checked", with the exact command for the user to run |

**vibe-check connector:** if tools from the vibe-check connector are available (for example `scan_live_site`, `crawl_app`, `check_supabase`, `check_email_domain`, `check_dependencies`, `save_report`), use them for the live and hosted checks and to save the report. Otherwise use the local tools and fallbacks above. Send the connector URLs, lockfiles and summaries only, never source code or secrets.
