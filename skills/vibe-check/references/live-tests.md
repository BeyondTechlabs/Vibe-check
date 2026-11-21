# Tests against the running app (staging or local only)

Load this file when the app can run locally or the user has a **staging or preview URL**, at the Full and Enterprise levels. Reading code shows what *should* happen; these tests show what *does* happen when someone actually tries. Each test is quick, safe and repeatable.

## Run them with `runtime.py` (don't improvise requests)

The tests are scripted, so results are the same every run and cost few tokens: the model fills in a plan and reads a summary.

1. **Ask once, as a choice** (the rules below). For each yes write it in `.vibe-check/answers.md`: `RUNTIME: yes`; and `RUNTIME: playwright: yes` if the user also agrees to install Playwright and Chromium for browser flows (with axe-core for the accessibility scan, about 300–500 MB, into `.vibe-check/runtime/`, never the project's `package.json`; if Chromium can't be downloaded, an installed Google Chrome is used). A staging host needs its own line: `RUNTIME: target staging.example.com: yes`. Production is refused by the script.
2. **Start the app locally** (the user's `BUILDS: yes` covers `npm run dev` and similar). If preview and production share a database, set up the safe test copy first (next section).
3. **Plan:** `python3 <skill-folder>/scripts/runtime.py . --plan` writes `.vibe-check/runtime/runtime.json` from the inventory. Fill it in from the code:
   - `base_url`;
   - `accounts` for test users A, B and admin (sign them up in the local app; their tokens or cookies stay in this git-ignored file and are never printed);
   - `authz`: every route and endpoint, with an ID owned by A and who may use it (`allow`), admin-only routes as `allow: ["admin"]`;
   - `login`, `endpoints` and `webhooks`;
   - `flows`: sign-up, sign-in, sign-out, password reset, the app's main path, and the test-mode payment marked `"payment": true`;
   - `pages`: the main pages for the phone-width check.
4. **Run:** `python3 <skill-folder>/scripts/runtime.py . --run all --consent` (after `--setup-browser --consent` for browser flows). It writes `.vibe-check/runtime/summary.md`.
5. **Use the results as evidence**, copied exactly: `| LIVE-002 | FAIL 🔬 Confirmed | RUN: runtime:authz-other-users → 1 case(s) where user B reached user A's data: … |`. `coverage.py` checks each against the saved result, its check, its verdict, its age and the user's `RUNTIME: yes`; a `CHECK: the running app → …` row is refused once the app was tested.
6. **Clean up:** delete the test accounts and test data you created.

`runtime.py` settles LIVE-002, LIVE-003, LIVE-004 and SEC-015 (who can reach what), SEC-055 (sensitive fields in responses), LIVE-006 and SEC-007 (rate limits), LIVE-007 (error leaks), SEC-037 (CORS), SEC-046 (headers), FIN-003 (webhook signatures), and in the browser LIVE-012 to LIVE-014 (flows, phone width, test payment), QA-016 (page and console errors), UX-001 and UX-003 (an axe scan for unnamed controls, clickable divs and missing alt text), and, when they fail, QA-003 (a journey broke) and UX-008 (overflow or buttons under 44px; a pass leaves UX-008 open, since modals aren't opened). Keyboard and screen-reader use (UX-002, LAW-005) still need a person. Uploads (LIVE-008), hunt proofs (LIVE-005) and the scanners (LIVE-009, LIVE-010) are still run by hand, with the same rules.

## When preview and production share one database

Many app builders (Lovable, Bolt, Replit) point the preview at the same database as the live app, so live tests there would touch real users. Don't skip the whole area silently: offer, as a choice, a **separate test copy** with its own database (duplicate or remix the project, or a database branch where the platform has one), with payments in test mode. If the user says no, the running-app items stay `CHECK: the running app → …`.

## The rules for live tests
- **Only with the user's OK, and never against production.** Ask once, as a choice, with the cost: *"Run the app locally and test it with two test accounts? Adds about 10–20 minutes. Nothing touches production."* · *Yes (Recommended)* · *Skip live tests*. Run it with a time limit (stop it when the tests end, and after 20 minutes at most). Without a yes, mark the tests `CAN'T TELL` with the exact command for the user. Production stays **read-only** (ground rule 6): GET and HEAD requests only.
- **Production data stays closed.** Never open, export or query a copy of production data (a database export, a backup, a `.wrangler` or `.sqlite` copy) without asking first, as a choice. If one is already in the project, report it (who could read it, should it be there?) and don't read it.
- **Passwords:** never test real users' passwords, not even offline against a copy, not even with a short list. What's allowed after a yes: checking whether an account still uses a password written in the project's own files (a seed or demo password in a README or seed script). Otherwise report the missing password rules (length, common-password list) and stop.
- **Test accounts and test data only.** Create or ask for two normal users (A and B) and, if there are roles, one of each. Use payment test modes (Stripe test keys, Razorpay test mode). Never real cards, real people's data or real emails.
- **Scanners use safe settings only:** passive or baseline modes, no denial-of-service, brute-force or fuzzing templates, low request rates, and stop as soon as anything looks unstable.
- **Save what you ran:** every command and its result goes in the ledger's *Tools run* table, and test scripts go in `.vibe-check/proofs/` (gitignored).

## Checks
- [ ] 🔴 LIVE-001 **The target is safe to test:** the user said yes, the URL is local or staging (not production: check the domain, the environment variables and the database it points at), payments are in test mode, and the data can be reset.
- [ ] 🔴 LIVE-002 **User B can't touch user A's things:** for every object type in the inventory (notes, orders, files, invoices, projects, messages…), user B tries to **read, list, update, delete and export** user A's item by its ID, through every API path including old versions. Every attempt must fail (403 or 404) and leave A's data unchanged.
- [ ] 🔴 LIVE-003 **Normal users can't use higher roles' functions:** a normal user calls every admin, staff, owner and internal endpoint and action. All are refused, including hidden ones that aren't linked in the UI.
- [ ] 🔴 LIVE-004 **Logged-out visitors are refused:** every non-public page and API route returns 401 or a redirect to sign-in with no data, including server actions, file URLs and realtime channels.
- [ ] 🟡 LIVE-005 **Hunt proofs re-run against the running app:** the race, replay and limit hypotheses from the hunt (Step 4a) are re-run as real parallel requests against the local or staging server, and the invariants hold.
- [ ] 🟡 LIVE-006 **Rate limits actually trigger:** repeated sign-in, sign-up, reset, OTP and expensive (AI, export, upload) requests get 429s at the documented limits, per user and per IP.
- [ ] 🟡 LIVE-007 **Errors stay quiet:** malformed JSON, wrong types, huge inputs, unknown routes and forced server errors return a friendly message, never a stack trace, SQL error, file path or framework debug page.
- [ ] 🟡 LIVE-008 **Uploads are really checked:** an SVG with a script, an HTML file renamed to `.jpg`, an oversized file and a ZIP with `../` paths are each rejected or made harmless, and uploaded files are served from a separate domain or with `Content-Disposition: attachment`.
- [ ] 🟡 LIVE-009 **OWASP ZAP baseline scan:** run ZAP's baseline (passive) scan against the staging URL, for example `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t <staging URL>`, and review each warning with the second look. If Docker or ZAP isn't available, say so in *Tools run*.
- [ ] 🟡 LIVE-010 **Known-issue templates (nuclei):** if `nuclei` is installed, run it against the staging URL with safe settings (exclude intrusive, DoS and fuzzing templates; low rate). Its community templates are updated as new vulnerabilities and misconfigurations are published. Review every match with the second look.
- [ ] 🟢 LIVE-011 **The tests can be re-run:** the two-account, role and logged-out tests are saved as scripts (in `.vibe-check/proofs/`), and offered to the user as permanent tests in their suite (only with their OK, under the scope guard).
- [ ] 🔴 LIVE-012 **The main flows work in a real browser:** sign-up, sign-in, sign-out, password reset and the app's main path complete, with no page errors, console errors or 5xx responses along the way.
- [ ] 🟡 LIVE-013 **Pages fit a phone screen:** the main pages don't scroll sideways at 375px wide.
- [ ] 🔴 LIVE-014 **The test-mode payment flow completes:** checkout in the processor's test mode finishes and the user gets what they paid for, once.
