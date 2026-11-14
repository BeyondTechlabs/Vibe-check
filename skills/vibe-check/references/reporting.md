# Reporting: what the report contains, saving, verifying and the chat

Read this at Step 5, before writing the report. The exact layouts are in `report-template.md`.

## First: ask the questions (before writing anything)

When every module is checked, collect the `CAN'T TELL` rows that start with `ASK:`. Tell the user how many and roughly how long (*"9 quick questions, about 2 minutes: they change your score"*), then ask them **as choices** (see *Asking the user* in SKILL.md): 4 per round, the most serious checks first, *Skip the rest* always allowed. Record each answer in `.vibe-check/answers.md` as `| ID | question | answer |` (or `skipped`), then act on it:

1. **Code before trust.** Look at the code the answer is about. If the code settles it, the code decides: PASS or FAIL with that evidence. When the code contradicts the answer, FAIL, and the finding says *"You said X; `file:line` shows Y"*. Only when the code can't decide does the answer settle it: `PASS` with `ANSWER: … · code: …` (shown as ✅ per your answer), `FAIL`, or a `CHECK:` row when the user should look.
2. **Follow-up checks.** If an answer adds to the profile (students or children, payments, health or financial data, users posting or chatting, other languages, AI features, EU users…), write `ADDS: <module>` in `.vibe-check/answers.md`, tell the user what it adds (*"Students use it: that adds 38 checks for student data, about 10 minutes"*) and check that module before the report. Any new `ASK:` items it raises are asked in one more round.
3. Re-run `coverage.py` and say what moved.

 `--verify-report` refuses a report while an `ASK:` item was neither asked nor skipped. In unattended runs, record `skipped: unattended`. Only then write the report, so the score reflects the answers.

**Without a question tool**, ask the same questions as a numbered list the user can answer in one line:
  ```text
  ❓ Q1 · Who uses your app?
     1. Adults only (Recommended: no age fields found in your code)
     2. Students or children
     3. Both
     4. Not sure
  ❓ Q2 · …
  Reply like: 1, 3   (one number per question, in order)
  ```

## Contents of the report, in this order

Use the format in `report-template.md`:

1. **How to read this** (the six-symbol line) and the **Result** block pasted from `coverage.py`: verdict, Score N/100 and band, *Since last check* when there's an earlier run, the totals table ("Checked N of M") and the area scorecard. Then one or two plain sentences on why.
2. **❌ Blockers:** each with plain-language impact, evidence, the fix, the **recipe** from `references/fixes.md` that covers its check ID, **safe to auto-fix: yes/no**, and a **copy-paste fix prompt**.
3. **⚠️ Fix before scale:** each with evidence, fix and safe to auto-fix.
4. **Questions for you** (every CAN'T TELL) and **Needs a lawyer**.
5. **What passed**, with evidence.
6. **Coverage and standards:** paste the tables `coverage.py` printed, including the **Standards** table (OWASP Top 10:2025, API Top 10, LLM Top 10, Mobile Top 10, ASVS 5.0 chapters and CWE Top 25, mapped in `references/standards.md`). Call it a coverage view, never a certification. Then paste the table `coverage.py` printed (one row per module: ✅ checked / ◐ partly / ❗ not checked / ➖ not applicable, with pass, fail, N/A, can't-tell and not-done counts). Never type these numbers yourself. Under it: the **inventory** counts (checked/found per category), the **sweep** summary (hits, findings, ruled out), the **Tools run** table, and the method for each module (tools or fallbacks). Every ◐ or ❗ says why and what would complete it.
7. **Not checked:** anything skipped, with the exact command or step for the user. Then **Only a human can confirm** (pentest, mobile binary review, legal sign-off, restore drill, and the standards items marked *Human*) and **When to run vibe-check again** (before each launch, after adding payments, sign-in, uploads, AI or a new country, and at least monthly).
8. **Score card** (plus, only for 🟢 on a Full or Enterprise check, the badge snippet and one ⭐ line), then the removable footer.

## Save, verify, keep

**Save** the full report to `.vibe-check/reports/YYYY-MM-DD.md`, and copy the ledger next to it as `.vibe-check/reports/YYYY-MM-DD-ledger.md` and make sure `.vibe-check/` is in `.gitignore` (add it if needed; this is the only file change allowed during the audit). Never save findings anywhere they could become public.

**Then verify the report against the ledger:** `python3 <skill-folder>/scripts/coverage.py --verify-report .vibe-check/reports/YYYY-MM-DD.md` must print `REPORT VERIFIED` (it checks the score, the totals, the coverage rows, the score card, one fix prompt per blocker and, when there's an earlier run, the *Since last check* line). **It also writes *Every check, with what was found* into the report** (each check's evidence from the ledger, grouped by area) so the user can see why something passed, at no extra cost, and **refuses the report if any project file changed since the audit started** without an approved fix card listing it. **It also refuses the report if the report, `.vibe-check/summary.md` or the ledger contains a full secret** (the same patterns `sweep.py` uses): mask it and verify again. If a number in the report doesn't match the ledger, fix the report (never the other way round). **Then keep the run:** `coverage.py --save` stores it in `.vibe-check/history/`, so the next run can show what was fixed, what's new and what came back. `.vibe-check/results.json` holds the same numbers for the badge and the opt-in stats.

## Optional, once: share anonymous counts

 In an interactive session (never unattended or scheduled), unless `.vibe-check/config` says `share_stats: false`, run `python3 <skill-folder>/scripts/share_stats.py` and ask in one line: *"Want to share these anonymous counts to help improve vibe-check? No code, file paths, names or URLs. Here's exactly what would be sent:"* followed by its output. Only if the user says yes, run it with `--send --yes`. If they say no, add `share_stats: false` to `.vibe-check/config` and never ask again. Never ask twice, and never let it delay the report.

## In the chat

Show the **one-screen summary** from `references/report-template.md` (*In the chat*), and save the same text as `.vibe-check/summary.md`: the verdict and score line, *Since last check*, the totals table and area scorecard pasted from `coverage.py`, every ❌ blocker as one plain sentence plus its file, the top 3 ⚠️ items, the counts of ❓ questions, ✅ passes and ➖ checks that don't apply, and the report path. Details come on request (*"explain 2"*). Then **ask the ❓ questions as choices** (*Asking the user*) and update the result with the answers. Then ask what to do next, as a choice: **Fix the N blockers** (Recommended when there are blockers) · **Fix everything I can do safely** · **Let me pick** · **Just the report for now**. End with: *You can say: "fix" · "fix all" · "fix 2" · "explain 2" · "check again" · "continue fixing" · "undo fix 2"*. If this was a Quick run, add: *"This was a Quick check (blind spots and blockers only). Say 'vibe check this app' for the full check."*

## Hand over the report (the user must be able to download it)

Saving the report in `.vibe-check/` isn't enough: it's a hidden folder. After `REPORT VERIFIED`:

1. Run `python3 <skill-folder>/scripts/report_pdf.py .vibe-check/reports/<date>.md`. It writes the PDF next to the report: the vibe-check band on every page, the score and verdict on the first page (from `results.json`, never typed), the same content as the `.md`. It runs on this computer and sends nothing; it refuses a report with an unmasked secret. If Python can't run here, say so and hand over the `.md` only.
2. **Give the user both files to download:** use the tool's file-sharing tool when there is one (for example `present_files`, `SendUserFile` or an attachment), so they appear as file cards. Without one, give the **full path** of each and the command to open it: `open "<path>"` (macOS), `xdg-open "<path>"` (Linux), `start "" "<path>"` (Windows).
3. Say in one line which to share: *"The PDF is the one to send to a co-founder or client; the .md is for AI tools."*

