# Live account checks (read-only)

Contents: When · Asking first · Running it · Using the results · What each account answers · Safety rules

Code shows what the app *should* do; the accounts show what's *actually* set. Reading the user's signed-in cloud and platform accounts settles many checks that would otherwise be `CHECK:` items for the user, and catches drift (the live database or settings disagree with the repo).

## When
After Step 2's scripts, run `python3 <skill-folder>/scripts/live.py . --detect`. It lists which tools are installed and look signed in (GitHub, Firebase, Supabase, Vercel, Netlify, AWS, Google Cloud, Azure, and Prowler). It reads nothing from any account. If none are signed in, skip this file: those checks stay `CHECK:` items.

## Asking first
Ask once, as a choice, listing the accounts that look signed in:
*"You're signed in to GitHub, Supabase and AWS here. May I read their settings, read-only? Nothing will be changed, no data is read, and results stay on this computer."* · *Yes, all of them (Recommended)* · *Choose which* · *No, skip live checks*.

For each yes, write `LIVE: <provider>: yes` in `.vibe-check/answers.md` (`github`, `firebase`, `supabase`, `vercel`, `netlify`, `aws`, `gcp`, `azure`). `live.py` refuses to read an account without that line and `--consent`; `coverage.py` refuses `LIVE:` evidence without it.

- **Read-only roles:** recommend them in one line: AWS *SecurityAudit* (or *ViewOnlyAccess*), Google Cloud *Security Reviewer* plus *Viewer*, Azure *Reader* plus *Security Reader*.
- **Supabase:** needs a read-only database connection that **the user sets themselves** in `VIBE_CHECK_DB_URL` (for example a role granted only `SELECT` on the catalog). Never ask for the connection string or password in the chat.
- **Several AWS profiles or Google Cloud projects:** ask which one is production (`--profile`, `--project`).
- **Prowler (optional, for AWS, Google Cloud and Azure):** a deeper open-source cloud scanner. If it isn't installed, ask before installing it (`pip install prowler`); it only reads.
- **Cloud module:** if the user says yes to AWS, Google Cloud or Azure and the profile didn't load `cloud-infra.md`, write `ADDS: cloud-infra` in `.vibe-check/answers.md`.

## Running it
```bash
python3 <skill-folder>/scripts/live.py . --run github --consent
python3 <skill-folder>/scripts/live.py . --run aws --consent --profile prod
python3 <skill-folder>/scripts/live.py . --run prowler-aws --consent --profile prod   # optional, takes longer
```
Each run writes `.vibe-check/live/<provider>.json` (raw results with a timestamp) and refreshes `.vibe-check/live/summary.md` (one line per result: id, checks, account, summary). Read the summary, not the raw files.

## Using the results
- **As evidence**, copy a result exactly: `| CLD-023 | FAIL 🔬 Confirmed | LIVE: aws:iam-user-mfa → console users without MFA: alice |`. `coverage.py` checks the result exists, belongs to that check, has the same verdict, was read within 30 days, and that the user said yes.
- **`check` results** (for example public buckets that may be deliberate) can't settle a PASS or FAIL alone: look at the code or ask, then decide.
- **Live beats CHECK:** when an account was read, a `CHECK:` row whose place is that account is refused. Use its live result instead.
- **Drift is a finding:** `supabase:drift-rls` (PLT-052) means production was changed by hand.
- **In the report**, add a *Live account checks* line to the header (which accounts, shortened IDs, when) and list each command in *Tools run*.

## What each account answers

| Account | Checks it can settle |
|---|---|
| GitHub | OPS-004, SUP-019, SEC-026 (secret scanning, push protection) · SUP-020 (branch protection) · SUP-009 (default token permission) · OPS-003 (Dependabot alerts) · VUL-005 (open critical/high alerts) · SUP-021 (organisation 2FA) |
| Supabase | PLT-001 (RLS on every table) · PLT-002 (policies allowing everything) · PLT-006 (views bypassing RLS) · PLT-004 (public buckets) · PLT-052 (drift from migrations) |
| Firebase | FBS-012 (separate projects) · FBS-013 (API key restrictions) |
| Vercel, Netlify | SEC-022 (secrets in browser-visible variables, by name; values are never read) |
| AWS | CLD-001, CLD-002, CLD-007, CLD-009, CLD-010, CLD-012, CLD-022, CLD-023 to CLD-028, CLD-030, CLD-032, CLD-033, CLD-037, CLD-039 |
| Google Cloud | CLD-001, CLD-010, CLD-012, CLD-028 to CLD-031, CLD-037, FBS-013 |
| Azure | CLD-001, CLD-010 to CLD-012, CLD-026, CLD-028, CLD-034, CLD-035 |
| Prowler | its findings mapped to the CLD checks above |

## Safety rules
- Only commands on `live.py`'s read-only allow-list run (list, describe, get, show, view; `SELECT` inside a read-only transaction). Anything else is refused by the script.
- It uses the user's existing login. It never asks for, stores or prints keys, tokens or passwords, and never reads secret values (env var values, secrets, parameters).
- It reads settings, never data: no listing objects in buckets, no reading user rows, no exports, no invoking functions.
- Results stay in `.vibe-check/live/` (git-ignored). Account IDs are shortened to their last 4 characters.
- It's not a penetration test: it reads configuration; it doesn't attack anything.
