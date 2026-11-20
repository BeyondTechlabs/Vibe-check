# Before you reply: self-check

Read this at the end of Step 5, before sending anything. Fix every unticked item first; this is the last loop, not a formality.

Go through this list and fix anything missing **before** sending the report:

- [ ] `profile.py` ran first; any answer that contradicts the code is listed under **Your answers vs your code**, and no module with code evidence was skipped without a `DEAD CODE:` proof.
- [ ] The independent re-check ran (`coverage.py --sample`, `R-` rows from a fresh helper or fresh pass), and anything overturned was changed.
- [ ] `coverage.py --verify-report` printed `REPORT VERIFIED` for the saved report.
- [ ] `inventory.py` and `sweep.py` ran (or the report says why not and the inventory and sweep were done by hand).
- [ ] `coverage.py` printed `COMPLETE`, or every remaining gap is a `CAN'T TELL` with its reason and listed under "Not checked". The coverage table and score line in the report are **pasted from its output**, not typed.
- [ ] The Standards table from `coverage.py` is in the report, called a coverage view (not a certification), plus *Only a human can confirm* and *When to run vibe-check again*.
- [ ] Live tests (`references/live-tests.md`) ran against local or staging with the user's OK, or are marked `CAN'T TELL` with the command, and nothing ran against production.
- [ ] The hunt ran (Full and Enterprise): a threat model, enough `T-` hypotheses across enough methods, every one proven, disproven or untested with evidence, and `PROVEN NEW` findings marked 🎯 *Found by hunting*.
- [ ] Every inventory category is accounted for (checked/found), every sweep hit has a verdict (FINDING or RULED OUT), and every component in `.vibe-check/versions.md` has a version verdict with its source.
- [ ] The *Tools run* table lists every tool tried, with its command and result, including "not installed".
- [ ] Every finding has evidence (`file:line`, command output, URL response or config value) and every 🔴 has a fix prompt.
- [ ] Every FAIL **quotes** its evidence (code lines re-read just now, or command output), and the line numbers match the current files.
- [ ] Every 🔴 and 🟡 had a second look, is labelled 🔬 Confirmed or 🔎 Likely, and each 🔴 says what was ruled out. Nothing labelled ❓ is presented as a blocker.
- [ ] Every legal, policy, platform or pricing statement comes from this skill's files or a source opened in this run (URL given). Nothing comes from memory.
- [ ] Every finding is marked safe to auto-fix yes/no.
- [ ] Findings carried over from an earlier run were re-checked and marked still open, fixed or new.
- [ ] No secrets are printed in full. The score card contains no private details.
- [ ] The report is saved, the path is given, and `.vibe-check/` is gitignored.
- [ ] The reply starts with `Running vibe-check v<version> · <level> check · <project name> (<skill folder>)`, the version is the latest (or the check couldn't connect), the project is the folder you were opened in (or the one the user named), and nothing from another project was reused. The report header shows the skill-files result (Step 0a), the vibe-check version and the Step 0 result: the update notice at the top if a newer version is out, or the "couldn't connect" line with the latest-release link.
- [ ] The chat shows the one-screen summary (saved as `.vibe-check/summary.md`) with the Result block pasted from `coverage.py`, the six symbols used only for their meanings, and the questions asked as choices (with the question tool when there is one).
- [ ] `coverage.py --save` stored this run in `.vibe-check/history/`.
- [ ] Build, lint, type-check and tests ran only after `BUILDS: yes`; fixes went where the user chose (separate copy, branch or patch files), and `.vibe-check/fix-log.md` says which.
- [ ] `codemap.py`, `autocheck.py` and `coverage.py --carry` ran before the modules (unless the user asked for a full re-run), helpers did only their IDs from `.vibe-check/redo.md`, and the report has the *Checks redone · carried over · settled by script* line.
- [ ] `report_pdf.py` made the PDF, and both the `.md` and the `.pdf` were handed over as downloadable files (or with full paths and an open command), not just saved.
- [ ] Every `ASK:` question was asked (as choices, before the report) or the user chose to skip it, and `.vibe-check/answers.md` records it; `CHECK:` items are in *🖥️ Check these yourself*, pasted from `coverage.py --check-list`. Every `CHECK:` was tried in the code and the database first (`tried:` names the search), questions in disguise were asked as questions, and the database question was asked if any item needed it. Each answer was checked against the code first; passes that rest on an answer alone are `ANSWER: … · code: …`, and every answer that added to the profile has an `ADDS:` line and its module was checked.
- [ ] The report has the *📚 Every check, with what was found* appendix written by `coverage.py` (not by hand), and the score card says `N blockers (M checks)`.
- [ ] No project file changed during the audit (the fingerprint guard passed), and "fix" was used only for approved code changes.
- [ ] Running the app, opening copies of production data and any password check were asked first, and no real user's password was tested.
- [ ] Modules the profile rules out have one `N/A` row each and their files were never opened.
- [ ] The reply ends with the next-step choice and the phrases the user can say.
