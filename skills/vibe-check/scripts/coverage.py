#!/usr/bin/env python3
"""vibe-check coverage: prove every check was done, by counting.

Compares the ledger (.vibe-check/ledger.md) with the skill's checklist and fails if any
required check ID has no result, if an ID was invented, if a result lacks evidence, if a
FAIL has no confidence label, if a sweep hit has no verdict, or if an inventory category
was never accounted for. It also prints the coverage table and score line for the report,
so the numbers in the report come from a count, not from memory.

Ledger rows (markdown table, one per check):
  | SEC-001 | PASS | src/lib/auth.ts:12 uses Supabase Auth |
  | SEC-030 | FAIL 🔬 Confirmed | app/notes/[id]/page.tsx:41 dangerouslySetInnerHTML on user text |
  | SEC-047 | CAN'T TELL | token generation lives in an external service; asked the user |
  | HLT-* | N/A | no health data (whole profile module) |
  | PLT-011..PLT-015 | N/A | not on Firebase |
  | INV-api_routes | 47/47 | every route traced to its auth check |
  | H-001..H-004 | RULED OUT | Supabase anon key: public by design, RLS on |
  | H-005 | FINDING SEC-022 | live Stripe key in src/lib/stripe.ts |
  | V-003 | OUTDATED | PHP 8.3.35 < 8.3.36 security release: https://www.php.net/releases/ (opened 2026-11-14) |
  | V-010..V-014 | CURRENT | npm audit --omit=dev: 0 vulnerabilities |
Results: PASS, FAIL (+ 🔬 Confirmed or 🔎 Likely), N/A, CAN'T TELL. Ranges and * are allowed for N/A only.
Core modules can't be N/A as a whole.

Usage:
  python3 coverage.py [LEDGER] [--level quick|full|enterprise] [--remaining]
    LEDGER       default .vibe-check/ledger.md (inventory.json and sweep.json are read from the same folder)
    --remaining  list what is left to check (use it to resume a long run)
    --save       after a complete count, keep this run in .vibe-check/history/ so the next run can compare
    --check-list print the check-yourself items grouped by place (one visit per place), for the report
    --brief MOD  print only the check lines a helper must do in module MOD (its IDs from redo.md), without the prose
    --part FILE  check only the rows in FILE (a helper's ledger.d/<module>.md) before the helper finishes
    --carry      before the helpers start: carry over every check whose wording and cited files are unchanged since the
                 last saved run (ledger.d/00-carried.md), and list the rest in .vibe-check/redo.md
  Every count also writes .vibe-check/results.json (score, band, totals, areas, every check's status).
Exit code 0 = complete, 1 = gaps found. Python 3.8+, standard library only.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
CORE = ["security", "reliability", "devops", "functional-qa", "legal-privacy", "launch-ux", "platforms",
        "lawsuits", "supply-chain", "vulnerabilities", "hunt", "maintainability"]
LAZY = {"ok", "fine", "looks fine", "looks good", "good", "yes", "pass", "passed", "n/a", "na", "none", "-", "checked",
        "done", "no issues", "nothing found", "all good", "seems fine", "looks ok", "verified", "correct"}
CT = "CAN'T TELL"
HUNT_METHODS = {"THREAT", "INVARIANT", "ABUSE", "PATH", "ASSUMPTION", "VARIANT", "CHAIN"}
SOURCE = re.compile(r"https?://|\b(?:npm audit|pnpm audit|yarn npm audit|composer audit|pip-audit|bundle audit|govulncheck|"
                    r"cargo audit|osv-scanner|trivy|docker scout|dependency-check|dotnet list package|wpscan|wp plugin list)\b", re.I)
CHECKABLE = re.compile(r"\w\.\w|/|`|:\d|https?:|\b(?:dashboard|config|setting|header|inventory|sweep|"
                       r"user confirmed|command|grep|npm|pnpm|yarn|pip|curl|git|gh|lighthouse|axe|playwright|policy|"
                       r"migration|env|DNS|SPF|DKIM|DMARC|CLI|SQL|screenshot)\b", re.I)
ID_RX = re.compile(r"^([A-Z0-9]+)-(\d{2,3})$")

# ---- score, bands and areas (v3.5). The score is counted here, never written by the AI. ----
WEIGHT = {"🔴": 3, "🟡": 2, "🟢": 1}
CAP_WITH_BLOCKERS = 69          # while any blocker (🔴 FAIL) is open, the score can't go above this
BANDS = [(90, "Ready to scale"), (75, "Ready to launch"), (60, "Needs work"), (0, "Not safe for real users yet")]
AREAS = [  # every checklist module belongs to exactly one area (validate.py checks this)
    ("AI blind spots", ["blind-spots"]),
    ("Security", ["security", "platforms", "supply-chain", "vulnerabilities", "cloud-infra", "desktop-extensions", "hunt", "live-tests",
                  "android", "ios", "mobile-frameworks", "firebase", "mobile-data"]),
    ("AI features", ["ai-features", "ai-agents"]),
    ("Payments", ["fintech"]),
    ("Privacy & legal", ["legal-privacy", "lawsuits", "policies", "kids-education", "health", "community"]),
    ("Reliability & ops", ["reliability", "devops", "maintainability", "enterprise"]),
    ("Launch & UX", ["functional-qa", "launch-ux", "mobile", "i18n"]),
]
# the six status symbols: one meaning each, everywhere
SYMBOLS = {"PASS": "✅", "BLOCKER": "❌", "SHOULD": "⚠️", "ASK": "❓", "NA": "➖", "FIXING": "🔧"}


def find_secrets(path: Path):
    """Lines in a report, summary or ledger that look like a full secret, using sweep.py's own secret patterns."""
    if not path.exists():
        return []
    import importlib.util
    spec = importlib.util.spec_from_file_location("_vc_sweep", Path(__file__).resolve().parent / "sweep.py")
    sw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sw)  # type: ignore[union-attr]
    found = []
    for n, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
        for pid, _cid, title, rx, _kind in sw.SECRET_KINDS:
            m = rx.search(line)
            if m and "…" not in m.group(0):
                found.append((n, pid, title))
                break
    return found


def band_of(score: int) -> str:
    return next(name for low, name in BANDS if score >= low)


def bar(score: int) -> str:
    n = max(0, min(10, round(score / 10)))
    return "█" * n + "░" * (10 - n)


EU_ONLY = set()   # 🔴 checks that block only for EU/EEA users: marked *(blocker for EU users)* in the checklist
ANSWER_ADDS = {}  # v3.6.7: things an answer added to the profile (module or 'eu-users') -> why, from answers.md 'ADDS:' lines
ON_WORD = re.compile(r"\b(?:user (?:confirmed|says|said|told)|per (?:the )?user|the user confirms|according to the user)\b", re.I)


def is_on_word(ev: str) -> bool:
    """A PASS that rests only on the user's answer (ANSWER: ... · code: ...)."""
    return ev.strip().upper().startswith("ANSWER:")


BUILD_CMD = re.compile(r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:build|test|lint|typecheck|type-check|check)\b|\btsc\b|"
                       r"\b(?:next|vite|astro|nuxt|turbo)\s+build\b|\bgradlew?\b|\bxcodebuild\b|\bflutter\s+(?:build|test|analyze)\b|"
                       r"\b(?:pytest|jest|vitest|eslint|playwright\s+test)\b|\bpod\s+install\b|\bexpo\s+(?:prebuild|run)\b|\beas\s+build\b")


def builds_problems(ledger_text: str, ans_text: str):
    """v3.8: builds, lint, type-checks and tests run only after the user said yes (BUILDS: yes in answers.md)."""
    m = re.search(r"^\s*[-*]?\s*BUILDS\s*:\s*(\w+)", ans_text, re.M | re.I)
    allowed = m.group(1).lower() if m else None
    sec = re.search(r"^##\s*Tools run\s*$(.*?)(?=^##\s|\Z)", ledger_text, re.M | re.S)
    if not sec:
        return []
    ran = [line.strip() for line in sec.group(1).splitlines()
           if line.strip().startswith("|") and BUILD_CMD.search(line) and not re.search(r"\bnot run\b", line, re.I)]
    if not ran or allowed == "yes":
        return []
    first = ran[0][:90]
    if allowed is None:
        return [f"TOOLS: {len(ran)} build, lint or test command(s) ran (e.g. {first}) without asking. Ask once: 'May I run your build, "
                f"lint and tests?' and write 'BUILDS: yes' or 'BUILDS: no' in .vibe-check/answers.md"]
    return [f"TOOLS: the user said no builds (BUILDS: {allowed}), but {len(ran)} build, lint or test command(s) ran (e.g. {first}). "
            f"Don't run them; mark them 'not run: you said no builds'"]


def load_answers(vc_dir: Path):
    """answers.md: '| ID | question | answer |' rows (answer 'skipped…' = not answered) and 'ADDS: <module> · <why>' lines."""
    path = vc_dir / "answers.md"
    text = path.read_text("utf-8") if path.exists() else ""
    answered = {}
    for line in text.splitlines():
        cells = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and ID_RX.match(cells[0]):
            answered[cells[0]] = not cells[2].lower().startswith("skipped")
    adds = {}
    for m in re.finditer(r"^\s*[-*]?\s*ADDS:\s*([\w-]+)\s*(?:[·:—-]\s*(.*))?$", text, re.M):
        adds[m.group(1).lower()] = (m.group(2) or "").strip() or "your answer"
    return text, answered, adds


def downgraded(cid, results):
    """A FAIL on an EU-only blocker, recorded as 'outside the EU', counts as should-fix."""
    if cid not in EU_ONLY or cid not in results:
        return False
    if "eu-users" in ANSWER_ADDS:   # an answer said there are EU users: the blocker stays a blocker
        return False
    blob = (results[cid][1] + " " + results[cid][2]).lower()
    return "outside the eu" in blob or "no eu users" in blob


ARROW = re.compile(r"\s*(?:→|->)\s*")
CODE_PLACE = re.compile(r"[\w/.-]+\.(?:tsx?|jsx?|mjs|py|sql|json|md|rb|go|php|vue|svelte|toml|ya?ml|html|css)\b|:\d+\b", re.I)
QUESTION_START = re.compile(r"^\s*(?:supply|provide|share|send|do you|does (?:your|the)|is there|are there|have you|has the)\b", re.I)
DB_PLACE = re.compile(r"\b(?:database|tables?|sql|pg_\w+|rls|row.level|polic(?:y|ies)|cron|grants?|views?|schema|triggers?|functions? in the database)\b", re.I)
CONCRETE = re.compile(r"`[^`]+`|[\w.-]+/[\w./*-]*|\w\.\w{2,4}\b|\b(?:rg|grep|SQL|select|find)\b|\"[^\"]{2,}\"|'[^']{2,}'", re.I)
NOT_SQL = re.compile(r"\b(?:backups?|pitr|point.in.time|restore|snapshots?)\b", re.I)


def check_parts(ev):
    """'CHECK: <place> → <what to look at> · tried: <what you searched first>' -> (place, what, tried)."""
    body = re.sub(r"^\s*CHECK\s*:\s*", "", ev, flags=re.I)
    m = re.search(r"[·;,]?\s*\btried\s*:\s*", body, re.I)
    head, tried = (body[:m.start()], body[m.end():]) if m else (body, "")
    parts = [x.strip(" ·;") for x in ARROW.split(head) if x.strip(" ·;")]
    place = " → ".join(parts[:-1]) if len(parts) > 1 else ""
    return place, (parts[-1] if parts else ""), tried.strip()


def check_problems(key, ev, have_sql, db_answer):
    """Why a CHECK: row isn't a real 'only you can look' item (empty list = fine)."""
    place, what, tried = check_parts(ev)
    out = []
    if re.search(r"\bANSWER\s*:", ev, re.I):
        return [f"{key}: this CHECK: already holds the user's answer: settle it (PASS with 'ANSWER: … · code: …', or FAIL)"]
    if QUESTION_START.search(place or what) or QUESTION_START.search(what):
        return [f"{key}: this is a question the user can answer from memory: make it 'ASK: <question>' and ask it as a choice"]
    if not place:
        out.append(f"{key}: write CHECK: as '<where, outside the code> → <what to look at> · tried: <what you searched first>'")
    elif CODE_PLACE.search(place):
        out.append(f"{key}: '{place[:40]}' is in the code: read it and decide (PASS/FAIL); CHECK: is only for places outside the code")
    if len(tried) < 15 or not CONCRETE.search(tried):
        out.append(f"{key}: say what you tried first, concretely: '· tried: `rg -i captcha src/` found nothing; it's set in the "
                   f"dashboard' (name the command, file, folder, query or search term)")
    if place and DB_PLACE.search(place + " " + what) and not NOT_SQL.search(place + " " + what):
        if have_sql:
            out.append(f"{key}: you have read-only database access: settle it with 'SQL: <query> → <result>' instead of CHECK:")
        elif db_answer is None:
            out.append(f"{key}: this is in the database: ask once 'May I read your database, read-only?' and write "
                       f"'DATABASE: yes' or 'DATABASE: no' in .vibe-check/answers.md")
        elif db_answer == "yes":
            out.append(f"{key}: the user allowed read-only database access: settle it with 'SQL: <query> → <result>'")
    return out


def check_groups(required, results, checks):
    """CHECK: items grouped by place, for one visit per place."""
    groups = {}
    for c in required:
        if status_of(c, results, checks) == "ASK" and ask_kind(c, results) == "check":
            place, what, _ = check_parts(results[c][1])
            groups.setdefault(place or "Other", []).append((c, what))
    return groups


def ask_kind(cid, results):
    """CAN'T TELL rows are either a question the user can answer (ASK:) or something only they can check (CHECK:)."""
    ev = results.get(cid, ("", "", ""))[1].strip().lower()
    return "check" if ev.startswith("check:") else "ask"


def status_of(cid, results, checks):
    """One of PASS, BLOCKER, SHOULD, ASK, NA, TODO for a check."""
    if cid not in results:
        return "TODO"
    r = results[cid][0]
    if r == "PASS":
        return "PASS"
    if r == "N/A":
        return "NA"
    if r == "CAN'T TELL":
        return "ASK"
    if checks[cid][1] == "🔴" and not downgraded(cid, results):
        return "BLOCKER"
    return "SHOULD"


def score_of(ids, results, checks):
    total = earned = 0
    for c in ids:
        st = status_of(c, results, checks)
        if st == "NA":
            continue
        w = WEIGHT["🟡" if downgraded(c, results) else checks[c][1]]
        total += w
        if st == "PASS":
            earned += w
    return (round(100 * earned / total) if total else 100), total


def skill_version() -> str:
    m = re.search(r'^\s*version:\s*"([^"]+)"', (SKILL / "SKILL.md").read_text("utf-8"), re.M)
    return m.group(1) if m else "?"


def compute_result(required, results, checks, level, date):
    counts = {k: 0 for k in ("PASS", "BLOCKER", "SHOULD", "ASK", "NA", "TODO")}
    for c in required:
        counts[status_of(c, results, checks)] += 1
    raw, _ = score_of(required, results, checks)
    capped = counts["BLOCKER"] > 0 and raw > CAP_WITH_BLOCKERS
    score = min(raw, CAP_WITH_BLOCKERS) if counts["BLOCKER"] else raw
    unresolved = sum(1 for c in required if status_of(c, results, checks) in ("ASK", "TODO") and checks[c][1] == "🔴")
    if counts["BLOCKER"]:
        verdict = "🔴 DO NOT SHIP"
    elif unresolved or score < 75:
        verdict = "🟡 SHIP AFTER FIXES"
    else:
        verdict = "🟢 SHIP"
    applicable = len(required) - counts["NA"]
    areas = []
    for name, mods in AREAS:
        ids = [c for c in required if checks[c][0] in mods]
        if not ids:
            continue
        st = [status_of(c, results, checks) for c in ids]
        app = sum(1 for s in st if s != "NA")
        if not app:
            areas.append({"area": name, "applies": False})
            continue
        sc, _ = score_of(ids, results, checks)
        areas.append({"area": name, "applies": True, "score": sc, "passed": st.count("PASS"), "applicable": app,
                      "blockers": st.count("BLOCKER"), "should": st.count("SHOULD"), "ask": st.count("ASK"), "todo": st.count("TODO")})
    return {
        "vibe_check_version": skill_version(), "date": date, "level": level, "verdict": verdict,
        "score": score, "raw_score": raw, "capped": capped, "band": band_of(score),
        "totals": {"in_vibe_check": len(checks), "at_this_level": len(required), "dont_apply": counts["NA"],
                   "apply": applicable, "passed": counts["PASS"], "blockers": counts["BLOCKER"], "should_fix": counts["SHOULD"],
                   "need_answer": counts["ASK"],
                   "on_your_word": sum(1 for c in required if status_of(c, results, checks) == "PASS" and is_on_word(results[c][1])), "not_done": counts["TODO"], "checked": applicable - counts["TODO"],
                   "questions": sum(1 for c in required if status_of(c, results, checks) == "ASK" and ask_kind(c, results) == "ask"),
                   "check_yourself": sum(1 for c in required if status_of(c, results, checks) == "ASK" and ask_kind(c, results) == "check"),
                   "check_places": len(check_groups(required, results, checks)),
                   "carried": sum(1 for c in required if c in results and results[c][1].lstrip().startswith("CARRIED")),
                   "by_script": sum(1 for c in required if c in results and results[c][1].lstrip().startswith("AUTO"))},
        "areas": areas,
        "blockers": [{"id": c, "name": checks[c][2]} for c in required if status_of(c, results, checks) == "BLOCKER"],
        "checks": {c: status_of(c, results, checks) for c in required},
    }


def compare_with_history(res, hist_dir: Path):
    """What changed since the newest saved run: fixed, new, came back, answered."""
    files = sorted(hist_dir.glob("*.json")) if hist_dir.exists() else []
    if not files:
        return None
    runs = []
    for f in files:
        try:
            runs.append(json.loads(f.read_text("utf-8")))
        except (ValueError, OSError):
            continue
    if not runs:
        return None
    prev = runs[-1]
    pc, now = prev.get("checks", {}), res["checks"]
    bad = ("BLOCKER", "SHOULD")
    ever_bad = {c for r in runs[:-1] for c, s in r.get("checks", {}).items() if s in bad}
    fixed = [c for c, s in now.items() if s == "PASS" and pc.get(c) in bad]
    came_back = [c for c, s in now.items() if s in bad and pc.get(c) == "PASS" and c in ever_bad]
    new = [c for c, s in now.items() if s in bad and pc.get(c) not in bad and c not in came_back]
    answered = [c for c, s in now.items() if pc.get(c) == "ASK" and s != "ASK"]
    return {"since": prev.get("date", files[-1].stem), "score_before": prev.get("score"), "score_now": res["score"],
            "band_before": prev.get("band"), "fixed": fixed, "new": new, "came_back": came_back, "answered": answered}


APPX_OPEN = "<!-- every-check: written by coverage.py from the ledger; don't edit by hand -->"
APPX_CLOSE = "<!-- /every-check -->"
LABEL = {"PASS": "✅", "BLOCKER": "❌", "SHOULD": "⚠️", "ASK": "❓", "NA": "➖", "TODO": "❗"}


def build_appendix(required, results, checks):
    """Every check with what was found, grouped by area, written by the script (costs no AI work)."""
    def cell(s):
        return re.sub(r"\s+", " ", s.replace("|", "/")).strip()[:220]
    out = [APPX_OPEN, "## 📚 Every check, with what was found", "",
           "Each row is copied from the ledger. ✅ rows show the evidence that it passed; ➖ rows say why it doesn't apply.", ""]
    for name, mods in AREAS:
        ids = [c for c in required if checks[c][0] in mods]
        if not ids:
            continue
        sts = {c: status_of(c, results, checks) for c in ids}
        if all(s == "NA" for s in sts.values()):
            reasons = sorted({cell(results[c][1]) for c in ids if c in results})[:2]
            out.append(f"**{name}** · ➖ doesn't apply ({len(ids)} checks): {'; '.join(reasons)}")
            out.append("")
            continue
        n_pass = sum(1 for s in sts.values() if s == "PASS")
        out += [f"### {name} · ✅ {n_pass} passed of {sum(1 for s in sts.values() if s != 'NA')}", "",
                "| | Check | What was found |", "|---|---|---|"]
        for want in ("BLOCKER", "SHOULD", "ASK", "TODO", "PASS", "NA"):
            for c in ids:
                if sts[c] == want:
                    ev = results[c][1] if c in results else "not checked yet"
                    mark = "✅ per your answer" if want == "PASS" and is_on_word(ev) else LABEL[want]
                    out.append(f"| {mark} | {c} {cell(checks[c][2])} | {cell(ev)} |")
        out.append("")
    out.append(APPX_CLOSE)
    return "\n".join(out)


def write_appendix(report_path: Path, block: str):
    """Put the appendix into the report (replacing an older one), just before the score card if there is one."""
    rep = report_path.read_text("utf-8")
    if APPX_OPEN in rep and APPX_CLOSE in rep:
        a = rep.index(APPX_OPEN); b = rep.index(APPX_CLOSE) + len(APPX_CLOSE)
        rep = rep[:a] + block + rep[b:]
    else:
        m = re.search(r"^#+\s*🏁", rep, re.M)
        rep = (rep[:m.start()] + block + "\n\n" + rep[m.start():]) if m else (rep.rstrip() + "\n\n" + block + "\n")
    report_path.write_text(rep, "utf-8")


FP_NAME = "fingerprint.json"   # written by profile.py at the start of the audit


def changed_since_fingerprint(root: Path, vc_dir: Path):
    """Project files (outside .vibe-check/) added, removed or changed since profile.py took the fingerprint."""
    fp = vc_dir / FP_NAME
    if not fp.exists():
        return None
    try:
        old = json.loads(fp.read_text("utf-8")).get("files", {})
    except ValueError:
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("_vc_profile", Path(__file__).resolve().parent / "profile.py")
    pr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pr)  # type: ignore[union-attr]
    now = pr.fingerprint(root)
    return sorted(k for k in set(old) | set(now) if old.get(k) != now.get(k))


def print_result(res, diff):
    t = res["totals"]
    cap = f" (capped: {t['blockers']} blocker{'s' if t['blockers'] != 1 else ''} open)" if res["capped"] else ""
    print("## Result (counted by coverage.py: paste this, never type these numbers)\n")
    print(f"**{res['verdict']} · Score {res['score']}/100{cap} · {res['band']}**\n")
    if diff:
        d = res["score"] - (diff["score_before"] or 0)
        print(f"Since last check ({diff['since']}): Score {diff['score_before']} → {res['score']} ({'+' if d >= 0 else ''}{d}) · "
              f"✅ {len(diff['fixed'])} fixed · 🆕 {len(diff['new'])} new · ↩️ {len(diff['came_back'])} came back · "
              f"❓ {len(diff['answered'])} answered\n")
        if diff["came_back"]:
            print(f"↩️ Came back (were fixed before): {', '.join(diff['came_back'])}\n")
    print("| Checks | Count |\n|---|---|")
    print(f"| In vibe-check | {t['in_vibe_check']} |")
    if t["at_this_level"] != t["in_vibe_check"]:
        print(f"| In this {res['level'].title()} check | {t['at_this_level']} |")
    print(f"| ➖ Don't apply to this app | {t['dont_apply']} |")
    print(f"| **Apply to this app** | **{t['apply']}** |")
    ow = t.get("on_your_word", 0)
    print(f"| ✅ Passed | {t['passed']}" + (f" ({ow} on your answer alone, not proven by the code)" if ow else "") + " |")
    print(f"| ❌ Must fix (blockers) | {t['blockers']} |")
    print(f"| ⚠️ Should fix | {t['should_fix']} |")
    print(f"| ❓ Need your answer | {t['need_answer']} ({t['questions']} questions · {t['check_yourself']} to check yourself in {t.get('check_places', 0)} place{'' if t.get('check_places', 0) == 1 else 's'}) |")
    if t["not_done"]:
        print(f"| ❗ Not checked yet | {t['not_done']} |")
    tail = "✅ nothing skipped" if not t["not_done"] else f"❗ {t['not_done']} not checked"
    print(f"| **Checked** | **{t['checked']} of {t['apply']}** · {tail} |\n")
    print(savings_line(t) + "\n")
    print("| Area | Score | Passed | ❌ Must fix | ⚠️ Should fix | ❓ Your answer |\n|---|---|---|---|---|---|")
    for a in res["areas"]:
        if not a["applies"]:
            print(f"| {a['area']} | ➖ doesn't apply | | | | |")
            continue
        dash = lambda n, s: f"{s} {n}" if n else "—"
        print(f"| {a['area']} | `{bar(a['score'])}` {a['score']} | {a['passed']}/{a['applicable']} | {dash(a['blockers'], '❌')} | "
              f"{dash(a['should'], '⚠️')} | {dash(a['ask'], '❓')} |")
    print()



# ---- v3.7: carry over unchanged checks, and checks settled by autocheck.py ----
CARRY_RX = re.compile(r"^\s*CARRIED from ([\d-]+) run \(([\w.-]+)\):\s*(.*)$", re.S)
_auto_cache = {}
_hist_cache = {}


def _sha(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()[:16]


def item_hashes():
    """A fingerprint of every check's wording, so a check whose text changed is always redone."""
    out = {}
    refs = SKILL / "references"
    bs = refs / "blind-spots.md"
    if bs.exists():
        for m in re.finditer(r"^\| (BS-\d{2}) \|(.*)$", bs.read_text("utf-8"), re.M):
            out[m.group(1)] = _sha(m.group(2).encode())
    for f in sorted(refs.glob("*.md")):
        for m in re.finditer(r"^- \[ \] (🔴|🟡|🟢) ([A-Z0-9]+-\d{3}) (.*)$", f.read_text("utf-8"), re.M):
            out[m.group(2)] = _sha((m.group(1) + m.group(3)).encode())
    return out


def file_hash(root: Path, rel: str):
    try:
        return _sha((root / rel).read_bytes())
    except OSError:
        return None


DOT_REF_RX = re.compile(r"(?<![\w/.@-])((?:[\w@()\[\].-]+/)*(?:\.[\w][\w.-]*|Gemfile|Rakefile|Procfile|Dockerfile|Makefile|"
                        r"Brewfile|Podfile|Jenkinsfile|Containerfile|LICENSE|CODEOWNERS)):(\d+)")


def cited_files(ev: str, root: Path):
    """The project files a piece of evidence cites, or None if one of them can't be found."""
    out = set()
    for m in list(REF_RX.finditer(ev)) + list(DOT_REF_RX.finditer(ev)):
        path, problem = resolve_cited(root, m.group(1))
        if path is None:
            return None
        try:
            out.add(path.relative_to(root.resolve()).as_posix())
        except ValueError:
            return None
    return sorted(out)


def profile_hash(vc: Path):
    """Which modules apply, from profile.json and any answers that added one."""
    try:
        mods = sorted(json.loads((vc / "profile.json").read_text("utf-8")).get("modules_with_evidence", {}))
    except (OSError, ValueError):
        mods = None
    ans = (vc / "answers.md").read_text("utf-8") if (vc / "answers.md").exists() else ""
    adds = sorted(re.findall(r"^\s*[-*]?\s*ADDS:\s*([\w-]+)", ans, re.M))
    return _sha(json.dumps([mods, adds]).encode())


NO_CARRY = re.compile(r"(?<![\w./-])(?:SQL|screenshot|ANSWER|AUTO|CARRIED|CHECK|ASK|LIVE|RUN)\s*:|`(?:npm|pnpm|yarn|npx|bun|curl|pip|pip-audit|osv-scanner|"
                      r"trivy|semgrep|nuclei|cargo|govulncheck|lighthouse|gh|supabase|firebase|vercel|wrangler)\b", re.I)


def carry_reason(cid, prev, items_now, root, vc):
    """None if a check from the previous run can be carried over unchanged, else why not."""
    got = prev.get("carry", {}).get("evidence", {}).get(cid)
    if not got:
        return "it wasn't a pass or N/A last time"
    status, ev = got
    if prev["carry"].get("items", {}).get(cid) != items_now.get(cid):
        return "the check's wording changed in this version"
    if NO_CARRY.search(ev):
        return "its evidence is a command, query, screenshot or answer, which is redone each time"
    files = cited_files(ev, root)
    if files is None:
        return "a file it cites is gone"
    if not files:
        if status == "N/A" and prev["carry"].get("profile") == profile_hash(vc):
            return None
        return "its evidence cites no file to prove it's unchanged"
    for rel in files:
        old = prev["carry"].get("files", {}).get(rel)
        if old is None or old != file_hash(root, rel):
            return f"{rel} changed"
    return None


def load_run(hist_dir: Path, run_id: str):
    if run_id not in _hist_cache:
        f = hist_dir / f"{run_id}.json"
        try:
            _hist_cache[run_id] = json.loads(f.read_text("utf-8"))
        except (OSError, ValueError):
            _hist_cache[run_id] = None
    return _hist_cache[run_id]


def autocheck_settle(root: Path):
    key = str(root)
    if key not in _auto_cache:
        spec = importlib.util.spec_from_file_location("vc_autocheck", Path(__file__).resolve().parent / "autocheck.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _auto_cache[key] = mod.settle(root)
    return _auto_cache[key]


LIVE_RX = re.compile(r"^\s*LIVE:\s*([\w-]+):([\w./-]+)\s*(?:→|->)\s*(.+?)\s*$", re.S)
_live_cache = {}


def load_live(vc: Path):
    if str(vc) not in _live_cache:
        res = {}
        for f in sorted((vc / "live").glob("*.json")) if (vc / "live").exists() else []:
            try:
                d = json.loads(f.read_text("utf-8"))
            except ValueError:
                continue
            if isinstance(d, dict) and "results" in d:
                for r in d["results"]:
                    res[r["id"]] = (d, r)
        _live_cache[str(vc)] = res
    return _live_cache[str(vc)]


def verify_live_row(key, r, ev, vc):
    """LIVE rows must copy a result live.py saved, for an account the user agreed to, with the same verdict."""
    m = LIVE_RX.match(ev)
    if not m:
        return [f"{key}: write live evidence as 'LIVE: <result id> → <summary>', copied from .vibe-check/live/summary.md"]
    rid = f"{m.group(1)}:{m.group(2)}"
    got = load_live(vc).get(rid)
    if not got:
        return [f"{key}: {rid} isn't in .vibe-check/live/: run live.py for that account (after the user's yes) and copy its result"]
    d, res = got
    base = d["provider"].split("-")[-1] if d["provider"].startswith("prowler") else d["provider"]
    ans = (vc / "answers.md").read_text("utf-8") if (vc / "answers.md").exists() else ""
    out = []
    if not d.get("consent") or not re.search(r"^\s*[-*]?\s*LIVE:\s*" + re.escape(base) + r"\s*:?\s*yes\b", ans, re.M | re.I):
        out.append(f"{key}: the live {base} account was read without a recorded yes: write 'LIVE: {base}: yes' in .vibe-check/answers.md after asking")
    if key not in res.get("checks", []):
        out.append(f"{key}: {rid} is evidence for {', '.join(res.get('checks', [])) or 'no check'}, not {key}")
    want = {"pass": "PASS", "fail": "FAIL"}.get(res["status"])
    if want and r != want:
        out.append(f"{key}: {rid} says {res['status']}, so the row must be {want}")
    if not want and r in ("PASS", "FAIL"):
        out.append(f"{key}: {rid} is only '{res['status']}' ({res['summary'][:60]}): it can't settle a PASS or FAIL alone")
    if m.group(3).strip() != res["summary"].strip():
        out.append(f"{key}: copy the summary of {rid} exactly: '{res['summary'][:90]}'")
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(d["time"])).days
        if age > 30:
            out.append(f"{key}: {rid} was read {age} days ago: run live.py again")
    except (KeyError, ValueError):
        pass
    return out


RUN_RX = re.compile(r"^\s*RUN:\s*(runtime:[\w./-]+)\s*(?:→|->)\s*(.+?)\s*$", re.S)


def load_runtime(vc: Path):
    try:
        d = json.loads((vc / "runtime" / "results.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None, {}
    return d, {r["id"]: r for r in d.get("results", [])}


def verify_run_row(key, r, ev, vc):
    """RUN rows must copy a result runtime.py saved, after the user's yes, with the same verdict."""
    m = RUN_RX.match(ev)
    if not m:
        return [f"{key}: write runtime evidence as 'RUN: <result id> → <summary>', copied from .vibe-check/runtime/summary.md"]
    d, res = load_runtime(vc)
    got = res.get(m.group(1))
    if not got:
        return [f"{key}: {m.group(1)} isn't in .vibe-check/runtime/results.json: run runtime.py (after the user's yes) and copy its result"]
    out = []
    ans = (vc / "answers.md").read_text("utf-8") if (vc / "answers.md").exists() else ""
    if not d.get("consent") or not re.search(r"^\s*[-*]?\s*RUNTIME:\s*yes\b", ans, re.M | re.I):
        out.append(f"{key}: the app was tested without a recorded yes: write 'RUNTIME: yes' in .vibe-check/answers.md after asking")
    if key not in got.get("checks", []):
        out.append(f"{key}: {m.group(1)} is evidence for {', '.join(got.get('checks', [])) or 'no check'}, not {key}")
    want = {"pass": "PASS", "fail": "FAIL"}.get(got["status"])
    if want and r != want:
        out.append(f"{key}: {m.group(1)} says {got['status']}, so the row must be {want}")
    if not want and r in ("PASS", "FAIL"):
        out.append(f"{key}: {m.group(1)} is only '{got['status']}': it can't settle a PASS or FAIL alone")
    if m.group(2).strip() != got["summary"].strip():
        out.append(f"{key}: copy the summary of {m.group(1)} exactly: '{got['summary'][:90]}'")
    try:
        if (datetime.now(timezone.utc) - datetime.fromisoformat(d["time"])).days > 30:
            out.append(f"{key}: the runtime tests are over 30 days old: run runtime.py again")
    except (KeyError, ValueError):
        pass
    return out


def verify_script_row(key, r, ev, root, vc):
    """AUTO rows must match what autocheck.py says now; CARRIED rows must prove their files are unchanged."""
    if re.match(r"^\s*AUTO\b", ev):
        now = autocheck_settle(root).get(key)
        if not now:
            return [f"{key}: autocheck.py doesn't settle this check here any more: re-run autocheck.py and check it yourself"]
        if now[0] != r or now[1].strip() != ev.strip():
            return [f"{key}: AUTO rows come only from autocheck.py, which now says '{now[0]}: {now[1][:80]}': re-run autocheck.py"]
        return []
    m = CARRY_RX.match(ev)
    if not m:
        return [f"{key}: carried rows are written by 'coverage.py --carry' only"]
    prev = load_run(vc / "history", m.group(2))
    if not prev or "carry" not in prev:
        return [f"{key}: carried from run {m.group(2)}, which isn't in .vibe-check/history/: check it again"]
    why = carry_reason(key, prev, item_hashes(), root, vc)
    if why:
        return [f"{key}: can't carry it over: {why}. Check it again"]
    if prev["carry"]["evidence"][key][0] != r or prev["carry"]["evidence"][key][1].strip() != m.group(3).strip():
        return [f"{key}: a carried row must keep its result and evidence exactly as in run {m.group(2)}"]
    return []


def write_carry(ledger_path: Path):
    """--carry: write ledger.d/00-carried.md and redo.md from the newest saved run."""
    vc = ledger_path.parent
    root = vc.resolve().parent
    hist = sorted((vc / "history").glob("*.json")) if (vc / "history").exists() else []
    prev = None
    for f in reversed(hist):
        data = load_run(vc / "history", f.stem)
        if data and "carry" in data:
            prev, run_id = data, f.stem
            break
    order, checks, _ = load_checklist()
    (vc / "ledger.d").mkdir(parents=True, exist_ok=True)
    if not prev:
        (vc / "ledger.d" / "00-carried.md").write_text("# Nothing carried over: no earlier complete run with file proofs\n", "utf-8")
        print("carry: no earlier saved run to carry from (runs saved by v3.7+ only): every check is checked fresh")
        return 0
    items_now = item_hashes()
    date = run_id[:10]
    rows, why_not = [], {}
    for cid in checks:
        why = carry_reason(cid, prev, items_now, root, vc)
        if why is None:
            status, ev = prev["carry"]["evidence"][cid]
            rows.append(f"| {cid} | {status} | CARRIED from {date} run ({run_id}): {ev} |")
        else:
            why_not[cid] = why
    head = ["# Carried over unchanged from the run of " + date + " (written by coverage.py --carry; don't edit).",
            "# Each row is re-proved when coverage.py counts: its check didn't change and the files it cites are byte-for-byte the same.",
            "", "| ID | Result | Evidence |", "|---|---|---|"]
    (vc / "ledger.d" / "00-carried.md").write_text("\n".join(head + rows) + "\n", "utf-8")
    redo = ["# Checks to do in this run (everything not carried over)", "",
            f"Carried over from {date}: {len(rows)}. To do: {len(why_not)}. A helper does only its module's IDs below.", ""]
    for mod in order:
        ids = [c for c in checks if checks[c][0] == mod and c in why_not]
        if ids:
            redo.append(f"## {mod} ({len(ids)})")
            redo.append(", ".join(ids))
            redo.append("")
    changed = sorted({w for w in why_not.values() if w.endswith(" changed")})
    if changed:
        redo += ["## Files changed since then", ""] + [f"- {w[:-8]}" for w in changed] + [""]
    (vc / "redo.md").write_text("\n".join(redo), "utf-8")
    tally = {}
    for w in why_not.values():
        k = "a cited file changed" if w.endswith(" changed") else w
        tally[k] = tally.get(k, 0) + 1
    print(f"carry: {len(rows)} checks carried over from the run of {date}; {len(why_not)} to do -> .vibe-check/redo.md")
    for k, v in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {v} to do because {k}")
    print(f"  files changed since then: {len(changed)}")
    return 0


def print_brief(module: str, vc: Path) -> int:
    """--brief <module>: just the check lines a helper must do (its IDs from redo.md, else the whole module), no prose."""
    f = SKILL / "references" / f"{module}.md"
    if not f.exists():
        print(f"No module '{module}'."); return 2
    text = f.read_text("utf-8")
    todo = None
    redo = vc / "redo.md"
    if redo.exists():
        m = re.search(r"^## " + re.escape(module) + r" \(\d+\)\n([^\n]*)", redo.read_text("utf-8"), re.M)
        todo = set(re.findall(r"[A-Z0-9]+-\d{3}", m.group(1))) if m else set()
    lines = re.findall(r"^- \[ \] ((?:🔴|🟡|🟢) ([A-Z0-9]+-\d{3}) .*)$", text, re.M)
    keep = [full for full, cid in lines if todo is None or cid in todo]
    head = text.split("\n## ", 1)[0].strip()
    where = re.search(r"^Where to look:.*$", text, re.M)
    print(f"# {module}: {len(keep)} check(s) to do" + (" (from redo.md)" if todo is not None else ""))
    if where:
        print("\n" + where.group(0))
    print()
    for line in keep:
        print("- " + line)
    if not keep:
        print("Nothing to do in this module: every check was carried over or settled by script.")
    del head
    return 0


def savings_line(t):
    redone = t["checked"] - t.get("carried", 0) - t.get("by_script", 0)
    return f"Checks redone: {redone} · carried over: {t.get('carried', 0)} · settled by script: {t.get('by_script', 0)}"


def load_checklist():
    """Return (ordered modules, {id: (module, severity, name)}, {prefix: module})."""
    checks, prefixes, modules = {}, {}, ["blind-spots"]
    bs_file = SKILL / "references" / "blind-spots.md"   # the blind spots live in their own file (v3.6)
    skill = bs_file.read_text("utf-8") if bs_file.exists() else (SKILL / "SKILL.md").read_text("utf-8")
    for num, sev, name in re.findall(r"^\| (BS-\d{2}) \| (🔴|🟡|🟢) \*\*(.+?)\*\*", skill, re.M):
        checks[num] = ("blind-spots", sev, name)
    prefixes["BS"] = "blind-spots"
    for f in sorted((SKILL / "references").glob("*.md")):
        text = f.read_text("utf-8")
        items = re.findall(r"^- \[ \] (🔴|🟡|🟢) ([A-Z0-9]+-\d{3}) (.*)$", text, re.M)
        if not items:
            continue
        modules.append(f.stem)
        for sev, cid, rest in items:
            if "*(blocker for EU users)*" in rest:
                EU_ONLY.add(cid)
            nm = re.match(r"\*\*(.+?)\*\*", rest)
            checks[cid] = (f.stem, sev, (nm.group(1) if nm else rest[:70]).rstrip(".:,"))
            prefixes[cid.split("-")[0]] = f.stem
    order = ["blind-spots"] + [m for m in CORE if m in modules] + [m for m in modules if m not in CORE and m != "blind-spots"]
    return order, checks, prefixes


REF_RX = re.compile(r"(?<![\w/.:@-])((?:\.{1,2}/)?(?:[\w@()\[\].-]+/)*(?:[\w@()\[\]-][\w@()\[\].-]*\.[A-Za-z]{1,8}|Dockerfile|Makefile|Procfile|Containerfile)):(\d+)(?:-(\d+))?")
CMD_WORDS = ("npm", "pnpm", "yarn", "npx", "bun", "curl", "git", "python", "python3", "pip", "pip-audit", "composer", "docker",
             "grep", "rg", "wp", "gh", "osv-scanner", "trivy", "semgrep", "nuclei", "bundle", "cargo", "govulncheck", "dotnet",
             "tsc", "eslint", "node", "deno", "supabase", "firebase", "vercel", "wrangler", "lighthouse", "zap-baseline.py")
_file_cache = {}


def _read(path: Path):
    if path not in _file_cache:
        try:
            _file_cache[path] = path.read_text("utf-8", "replace") if path.is_file() and path.stat().st_size < 5_000_000 else None
        except OSError:
            _file_cache[path] = None
    return _file_cache[path]


_index = {}


def project_files(root: Path):
    """Every file in the project (same skips as the scripts), for resolving shortened paths."""
    if root not in _index:
        skip = {"node_modules", ".git", ".next", ".nuxt", ".svelte-kit", ".output", "dist", "build", "out", "coverage",
                ".vibe-check", "vendor", ".venv", "venv", "__pycache__", ".turbo", ".vercel", ".netlify", ".expo", "Pods",
                "target", ".gradle", ".idea", ".cache", ".wrangler"}
        files = []
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in skip]
            files += [(Path(dp) / f).relative_to(root).as_posix() for f in fn]
        _index[root] = files
    return _index[root]


def resolve_cited(root: Path, rel: str):
    """A cited path as written, or the one project file it uniquely shortens (routes.ts:12 → server/routes.ts)."""
    path = (root / rel).resolve()
    if _read(path) is not None:
        return path, None
    matches = [f for f in project_files(root) if f == rel or f.endswith("/" + rel.lstrip("./"))]
    if len(matches) == 1:
        return (root / matches[0]).resolve(), None
    if len(matches) > 1:
        return None, f"{rel} matches {len(matches)} files ({', '.join(matches[:3])}…): write the full path"
    return None, f"{rel} doesn't exist in the project"


def closest_line(texts, quote):
    import difflib
    lines = [ln.strip() for t in texts for ln in t.splitlines() if len(ln.strip()) > 6]
    best = difflib.get_close_matches(quote.strip(), lines, n=1, cutoff=0.5)
    return best[0][:90] if best else None


def check_evidence(key: str, ev: str, root: Path):
    """Problems with the evidence: cited files or lines that don't exist, quoted code that isn't in the cited files.
    Forgiving where it's harmless (a shortened path that matches one file, spacing and quote style in code) and
    specific where it isn't, so a ledger can be corrected in one pass instead of a rewrite loop."""
    problems, cited = [], []
    for m in REF_RX.finditer(ev):
        rel, line = m.group(1), int(m.group(2))
        path, why = resolve_cited(root, rel)
        text = _read(path) if path else None
        if text is None:
            problems.append(f"{key}: evidence cites {rel}:{line}, but {why}")
            continue
        n_lines = text.count("\n") + 1
        if line < 1 or line > n_lines + 1:
            problems.append(f"{key}: evidence cites {rel}:{line}, but {rel} has only {n_lines} lines")
            continue
        cited.append(text)
    if cited:
        def _n(s):
            return re.sub(r"\s+", " ", s.replace('"', "'").replace("`", "'")).strip().rstrip(";,")
        norm_files = [_n(t) for t in cited]
        for span in re.findall(r"`([^`]{8,200})`", ev):
            s = span.strip()
            if "…" in s or "..." in s or s.split(" ")[0] in CMD_WORDS or " --" in s or REF_RX.fullmatch(s):
                continue
            if not re.search(r"[(){}\[\]=<>;.'\"/]|[a-z][A-Z]", s):
                continue
            ns = _n(s)
            if not any(ns in f for f in norm_files):
                near = closest_line(cited, s)
                problems.append(f"{key}: quoted code `{s[:50]}` isn't in the cited file(s)"
                                + (f"; the closest line there is `{near}`: quote that, or cite the right file" if near
                                   else ": re-read the file and quote it exactly"))
    return problems


def app_size(vc: Path):
    """small / medium / large, from the number of code files in the code map (None if there's no map)."""
    try:
        n = len(json.loads((vc / "codemap.json").read_text("utf-8")).get("files", {}))
    except (OSError, ValueError):
        return None, 0
    return ("small" if n <= 50 else "medium" if n <= 200 else "large"), n


def sample_ids(results, checks, seed: str, size=None):
    """Deterministic re-check sample: every 🔴 FAIL (up to 25), plus PASS rows (5 on a small app, 12 otherwise),
    picked by a hash of the ledger date. Carried and script-settled rows are proved by the scripts, so they're left out."""
    import hashlib
    h = lambda c: hashlib.sha256((seed + c).encode()).hexdigest()
    by_model = lambda r: not re.match(r"^\s*(AUTO|CARRIED)\b", r[1])
    fails = sorted([c for c, r in results.items() if r[0] == "FAIL" and checks.get(c, ("", ""))[1] == "🔴" and by_model(r)], key=h)[:25]
    passes = sorted([c for c, r in results.items() if r[0] == "PASS" and by_model(r)], key=h)[:5 if size == "small" else 12]
    return fails + passes


def load_standards():
    """Return [(standard title, [(item id, name, [check ids], human note)])] from references/standards.md."""
    path = SKILL / "references" / "standards.md"
    if not path.exists():
        return []
    out, cur = [], None
    for line in path.read_text("utf-8").splitlines():
        if line.startswith("## "):
            cur = (line[3:].strip(), [])
            out.append(cur)
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.startswith("|") else []
        if cur and len(cells) == 3 and cells[0] not in ("ID",) and not set(cells[0]) <= set("-: "):
            ids = re.findall(r"\b(?:BS-\d{2}|[A-Z]+-\d{3})\b", cells[2])
            human = "Human:" in cells[2]
            cur[1].append((cells[0], cells[1], ids, human))
    return [s for s in out if s[1]]


def expand(token: str, checks, prefixes):
    """Expand 'SEC-001', 'SEC-001..SEC-010' or 'HLT-*' into IDs. Returns (ids, kind, error)."""
    token = token.strip().strip("`")
    if token.endswith("-*"):
        pre = token[:-2]
        if pre not in prefixes:
            return [], "wild", f"unknown module prefix '{pre}'"
        return [c for c in checks if c.split("-")[0] == pre], "wild", None
    if ".." in token:
        a, b = [x.strip() for x in token.split("..", 1)]
        ma, mb = ID_RX.match(a), ID_RX.match(b)
        if not (ma and mb) or ma.group(1) != mb.group(1):
            return [], "range", f"bad range '{token}'"
        lo, hi, width = int(ma.group(2)), int(mb.group(2)), len(ma.group(2))
        ids = [f"{ma.group(1)}-{n:0{width}d}" for n in range(lo, hi + 1)]
        unknown = [i for i in ids if i not in checks]
        return [i for i in ids if i in checks], "range", (f"range '{token}' includes unknown IDs {unknown[:3]}" if unknown else None)
    return [token], "one", (None if token in checks else f"unknown check ID '{token}' (not in the checklist: invented?)")


def norm_result(r: str):
    u = r.upper().replace("’", "'")
    if u.startswith("PASS"):
        return "PASS"
    if u.startswith("FAIL"):
        return "FAIL"
    if u.startswith("N/A") or u.startswith("NA ") or u == "NA" or u.startswith("NOT APPLICABLE"):
        return "N/A"
    if u.startswith("CAN'T TELL") or u.startswith("CANT TELL") or u.startswith("CANNOT TELL"):
        return "CAN'T TELL"
    return None


def main() -> int:
    argv = sys.argv[1:]
    level = None
    if "--level" in argv:
        i = argv.index("--level"); level = argv[i + 1].lower(); del argv[i:i + 2]
    remaining_only = "--remaining" in argv
    want_sample = "--sample" in argv
    want_fix_plan = "--fix-plan" in argv
    want_save = "--save" in argv
    want_check_list = "--check-list" in argv
    part_file = None
    if "--part" in argv:
        i = argv.index("--part"); part_file = Path(argv[i + 1]); del argv[i:i + 2]
    if "--brief" in argv:
        i = argv.index("--brief"); mod = argv[i + 1]; del argv[i:i + 2]
        rest = [a for a in argv if not a.startswith("--")]
        return print_brief(mod, Path(rest[0] if rest else ".vibe-check/ledger.md").parent)
    report_path = None
    if "--verify-report" in argv:
        i = argv.index("--verify-report"); report_path = Path(argv[i + 1]); del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    ledger_path = Path(args[0] if args else ".vibe-check/ledger.md")
    if "--carry" in argv or "--carry" in sys.argv:
        return write_carry(ledger_path)
    if not ledger_path.exists():
        print(f"No ledger at {ledger_path}. Create it first (see SKILL.md Step 4).")
        return 1
    text = ledger_path.read_text("utf-8")
    # helpers working in parallel each write .vibe-check/ledger.d/<module>.md; read them as one ledger
    for part in sorted((ledger_path.parent / "ledger.d").glob("*.md")):
        text += "\n" + part.read_text("utf-8")
    root = ledger_path.resolve().parent.parent
    seed_m = re.search(r"^\s*Date:\s*(.+)$", text, re.M)
    seed = seed_m.group(1).strip() if seed_m else root.name
    if level is None:
        m = re.search(r"^\s*Level:\s*\**\s*(quick|full|launch|enterprise|re-?check)", text, re.I | re.M)
        level = (m.group(1).lower() if m else "full")
    level = "full" if level in ("launch", "recheck", "re-check") else level   # a re-check is a Full count with carried rows

    order, checks, prefixes = load_checklist()
    errors, warns = [], []
    ans_text, answered, adds = load_answers(ledger_path.parent)
    errors.extend(builds_problems(text, ans_text))
    ANSWER_ADDS.clear(); ANSWER_ADDS.update(adds)
    known_mods = {v[0] for v in checks.values()}
    for a in adds:
        if a != "eu-users" and a not in known_mods:
            errors.append(f"answers.md: 'ADDS: {a}' isn't a module; use one of: eu-users, " + ", ".join(sorted(known_mods)))
    results = {}   # id -> (result, evidence, confidence)
    inv_rows, hit_rows, ver_rows = {}, {}, {}
    hunt_rows = []
    recheck_rows = {}
    evidence_problems = []
    pass_evidence = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.strip().startswith("|") else []
        if len(cells) < 3 or set(cells[0]) <= set("-: ") or cells[0].lower() in ("id", "check", "hit"):
            continue
        key, res, ev = cells[0].strip("`"), cells[1], " | ".join(cells[2:]).strip()
        if re.match(r"^T-\d+$", key):
            hunt_rows.append((key, cells))
            if len(cells) >= 5 and cells[3].upper().startswith(("PROVEN", "DISPROVEN")):
                evidence_problems += check_evidence(key, " | ".join(cells[4:]), root)
            continue
        if re.match(r"^R-\d+$", key):
            if len(cells) < 4:
                errors.append(f"{key}: re-check rows are | R-001 | <check ID> | CONFIRMED or OVERTURNED | evidence |")
            else:
                recheck_rows[cells[1].strip("` ")] = (key, cells[2].upper().strip(), " | ".join(cells[3:]))
                evidence_problems += check_evidence(key, " | ".join(cells[3:]), root)
            continue
        if key.startswith("INV-"):
            inv_rows[key[4:]] = (res, ev)
            continue
        if key.startswith("V-"):
            m = re.match(r"^V-(\d+)(?:\s*\.\.\s*V-(\d+))?$", key)
            if not m:
                errors.append(f"{key}: components are written V-001 or V-001..V-009")
                continue
            for n in range(int(m.group(1)), int(m.group(2) or m.group(1)) + 1):
                ver_rows[f"V-{n:03d}"] = (res, ev)
            continue
        if key.startswith("H-"):
            m = re.match(r"^H-(\d+)(?:\s*\.\.\s*H-(\d+))?$", key)
            if not m:
                errors.append(f"{key}: sweep hits are written H-001 or H-001..H-009")
                continue
            for n in range(int(m.group(1)), int(m.group(2) or m.group(1)) + 1):
                hit_rows[f"H-{n:03d}"] = (res, ev)
            continue
        if not re.match(r"^[A-Z0-9]+-(\d|\*)", key):
            continue
        r = norm_result(res)
        if r is None:
            errors.append(f"{key}: result must be PASS, FAIL, N/A or CAN'T TELL (got '{res}')")
            continue
        ids, kind, e = expand(key, checks, prefixes)
        if e:
            errors.append(e)
        if kind != "one" and r != "N/A":
            errors.append(f"{key}: ranges and * are only allowed for N/A (each {r} needs its own row and evidence)")
            continue
        if kind == "wild" and ids and checks[ids[0]][0] in CORE:
            errors.append(f"{key}: core module '{checks[ids[0]][0]}' can't be N/A as a whole; mark sections or items")
        if not ev or ev.lower().strip(" .") in LAZY or len(ev) < 8:
            errors.append(f"{key}: {r} needs real evidence or a reason (got '{ev or 'nothing'}')")
        if r == "CAN'T TELL" and not re.match(r"^\s*(ASK|CHECK)\s*:", ev, re.I):
            errors.append(f"{key}: CAN'T TELL starts with ASK: (a question the user can answer) or CHECK: (something only they can "
                          f"check, e.g. a dashboard setting), then the reason (got '{ev[:50]}')")
        if r == "PASS" and is_on_word(ev):
            # code before trust: say what code you looked at and why it can't decide
            if not re.search(r"\bcode:\s*\S.{6,}", ev, re.I):
                errors.append(f"{key}: an ANSWER: pass must also say what code you checked first: "
                              f"'ANSWER: <their answer> · code: <what you looked at, and why it can't decide>'")
        elif r == "PASS" and (ON_WORD.search(ev) or answered.get(key)) and not re.search(r":\d|`[^`]+`|https?://", ev):
            errors.append(f"{key}: this pass rests on the user's answer: write it 'ANSWER: <answer> · code: <what you checked>' "
                          f"(shown as ✅ per your answer), or cite the code that proves it")
        on_word = r == "PASS" and is_on_word(ev)
        by_script = bool(re.match(r"^\s*(AUTO|CARRIED)\b", ev)) and r in ("PASS", "FAIL", "N/A")
        if by_script:
            errors.extend(verify_script_row(key, r, ev, root, ledger_path.parent))
            on_word = True    # proved by the script, not by a quote
        if re.match(r"^\s*LIVE\s*:", ev):
            errors.extend(verify_live_row(key, r, ev, ledger_path.parent))
            on_word = True    # proved by live.py's saved result
        if re.match(r"^\s*RUN\s*:", ev):
            errors.extend(verify_run_row(key, r, ev, ledger_path.parent))
            on_word = True    # proved by runtime.py's saved result
        if r in ("PASS", "FAIL") and not on_word:
            evidence_problems += check_evidence(key, ev, root)
        if r in ("PASS", "FAIL") and not on_word and not CHECKABLE.search(ev):
            errors.append(f"{key}: {r} evidence must point to something checkable (file:line, command, URL, "
                          f"config value, dashboard setting or inventory/sweep item), got '{ev[:60]}'")
        if r == "PASS":
            pass_evidence.setdefault(ev.lower(), []).append(key)
        conf = ""
        if r == "FAIL":
            if "confirmed" in res.lower() or "✅" in res or "🔬" in res:
                conf = "Confirmed"
            elif "likely" in res.lower() or "🔎" in res:
                conf = "Likely"
            else:
                errors.append(f"{key}: FAIL needs a confidence label (🔬 Confirmed or 🔎 Likely); unsure items are CAN'T TELL")
        for cid in ids:
            if cid in results and results[cid][0] != r:
                errors.append(f"{cid}: two different results ({results[cid][0]} and {r})")
            results[cid] = (r, ev, conf)

    for ev, keys in pass_evidence.items():
        if len(keys) > 3:
            errors.append(f"same PASS evidence copied onto {len(keys)} rows ({', '.join(keys[:4])} …): "
                          "each check needs its own evidence, or it wasn't really checked")

    # required set
    if level == "quick":
        required = [c for c, (m, s, _) in checks.items() if m == "blind-spots" or (m in CORE and s == "🔴")]
    else:
        required = list(checks)
        if level == "enterprise":
            for mod in ("enterprise", "policies"):
                if all(results.get(c, ("",))[0] == "N/A" for c, v in checks.items() if v[0] == mod):
                    errors.append(f"Enterprise level: module '{mod}' can't be N/A as a whole")
    missing = [c for c in required if c not in results]
    errors += evidence_problems[:40]
    if len(evidence_problems) > 40:
        errors.append(f"…and {len(evidence_problems) - 40} more evidence problems")

    sample = sample_ids(results, checks, seed, app_size(ledger_path.parent)[0]) if level in ("full", "enterprise") else []
    if want_sample:
        print("Independent re-check sample (have a fresh helper, or a fresh pass that re-reads the files, check each one):")
        for c in sample:
            print(f"  {c}  {results[c][0]}  {checks[c][2]}  ({results[c][1][:70]})")
        print("Record each as | R-001 | <ID> | CONFIRMED or OVERTURNED | evidence |. If OVERTURNED, change that check's result.")
        return 0
    if sample and not missing:
        no_row = [c for c in sample if c not in recheck_rows]
        if no_row:
            errors.append(f"independent re-check: {len(no_row)} sampled checks have no R- row ({', '.join(no_row[:8])}"
                          f"{' …' if len(no_row) > 8 else ''}). Run coverage.py --sample, and have a fresh helper re-check them")
        for c in sample:
            if c in recheck_rows:
                rk, verdict, rev = recheck_rows[c]
                if not verdict.startswith(("CONFIRMED", "OVERTURNED")):
                    errors.append(f"{rk}: verdict must be CONFIRMED or OVERTURNED")
                elif len(rev) < 8 or not CHECKABLE.search(rev):
                    errors.append(f"{rk}: the re-check needs its own evidence (file:line, command or setting)")
                elif verdict.startswith("OVERTURNED") and results[c][0] == "PASS":
                    errors.append(f"{rk}: {c} was overturned by the re-check but is still PASS: change its result")

    if want_check_list:
        groups = check_groups(required, results, checks)
        total = sum(len(v) for v in groups.values())
        print(f"## 🖥️ Check these yourself\n\n{total} items in {len(groups)} places: open each place once, tick what's true, "
              "or paste a screenshot and I'll read it.\n")
        for place, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            mins = max(2, round(len(items) * 0.5 + 1))
            print(f"### {place} ({len(items)} item{'s' if len(items) != 1 else ''}, about {mins} min)\n")
            for c, what in items:
                print(f"- [ ] **{c}** {checks[c][2]}: {what}")
            print()
        return 0

    if want_fix_plan:
        plan = ledger_path.parent / "fix-plan.md"
        old = {}
        if plan.exists():
            for line in plan.read_text("utf-8").splitlines():
                cells = [x.strip() for x in line.strip().strip("|").split("|")]
                if len(cells) >= 7 and re.match(r"^[A-Z0-9]+-\d{2,3}$|^T-\d+$", cells[1]):
                    old[cells[1]] = cells[4:7]
        recipe_of = {}
        fx = SKILL / "references" / "fixes.md"
        if fx.exists():
            for m in re.finditer(r"^### (.+)\n\*\*Covers:\*\* (.+)$", fx.read_text("utf-8"), re.M):
                for cid in re.findall(r"\b(?:BS-\d{2}|[A-Z]+-\d{3})\b", m.group(2)):
                    recipe_of.setdefault(cid, m.group(1).strip())
        items = [(c, checks[c][1], checks[c][2], results[c]) for c in results if c in checks and results[c][0] in ("FAIL", "CAN'T TELL")]
        items.sort(key=lambda x: ({"🔴": 0, "🟡": 1, "🟢": 2}[x[1]], 0 if x[3][0] == "FAIL" else 1, x[0]))
        new_hunt = [(k, cells) for k, cells in hunt_rows if len(cells) >= 5 and cells[3].upper().startswith("PROVEN NEW")]
        out = ["# vibe-check fix plan", "", "Statuses: `TODO`, `IN PROGRESS`, `NEEDS DECISION`, `DONE`, `BLOCKED` (with why). "
               "A fix is only `DONE` when its check was re-run and passes (Verified = how). Generated by `coverage.py --fix-plan`; "
               "re-running it keeps the statuses.", "",
               "| # | ID | Severity | Item | Status | Decision needed | Verified | Recipe (fixes.md) |", "|---|---|---|---|---|---|---|---|"]
        n = 0
        for c, sev, name, r in items:
            n += 1
            st, dec, ver = old.get(c, ["TODO", "-" if r[0] == "FAIL" else "answer the question first", "-"])
            label = name + (" (can't tell yet)" if r[0] == CT else "")
            out.append("| %d | %s | %s | %s | %s | %s | %s | %s |" % (n, c, sev, label, st, dec, ver, recipe_of.get(c, "-")))
        for k, cells in new_hunt:
            n += 1
            st, dec, ver = old.get(k, ["TODO", "-", "-"])
            out.append(f"| {n} | {k} | 🎯 | {cells[1][:80]} | {st} | {dec} | {ver} | Logic bugs found by hunting |")
        plan.write_text("\n".join(out) + "\n")
        print(f"fix plan: {n} items -> {plan}")
        return 0

    # profile from the code: a module the code shows can't be N/A as a whole (answers can't remove evidence)
    prof_path = ledger_path.parent / "profile.json"
    if prof_path.exists():
        must = json.loads(prof_path.read_text("utf-8")).get("modules_with_evidence", {})
    else:
        must = {}
    # v3.6.11: CHECK: only for places outside the code and database, after trying them first
    have_sql = any(re.search(r"\bSQL\s*:", v[1]) for v in results.values())
    dbm = re.search(r"^\s*[-*]?\s*DATABASE\s*:\s*(\w+)", ans_text, re.M | re.I)
    db_answer = dbm.group(1).lower() if dbm else None
    db_answer = "yes" if db_answer in ("yes", "y", "allowed") else ("no" if db_answer else None)
    live_read = {d["provider"].split("-")[-1] for d, _ in load_live(ledger_path.parent).values()}
    live_names = {"github": ("github",), "aws": ("aws", "amazon"), "gcp": ("google cloud", "gcp", "gcloud"), "azure": ("azure",),
                  "firebase": ("firebase",), "supabase": ("supabase",), "vercel": ("vercel",), "netlify": ("netlify",)}
    for c, v in results.items():
        if v[0] == "CAN'T TELL" and ask_kind(c, results) == "check":
            errors.extend(check_problems(c, v[1], have_sql, db_answer))
            place = check_parts(v[1])[0].lower()
            hit = next((pv for pv in live_read for nm in live_names.get(pv, ()) if nm in place), None)
            if "running app" in place and load_runtime(ledger_path.parent)[1] and "runtime.py" not in v[1]:
                errors.append(f"{c}: the running app was tested: settle this with a result from .vibe-check/runtime/summary.md "
                              f"('RUN: <id> → <summary>'), or say in tried: why runtime.py can't test it")
            if hit and "live.py" not in v[1]:
                errors.append(f"{c}: the live {hit} account was read: settle this with its result from .vibe-check/live/summary.md "
                              f"('LIVE: <id> → <summary>') instead of a CHECK:, or say in tried: why live.py can't read it")
    # v3.6.7: an answer that adds to the profile (students, payments, health…) makes that module required too
    for a, why in adds.items():
        if a != "eu-users":
            must.setdefault(a, [f"your answer: {why}"])
    if must:
        for mod, where in must.items():
            ids = [c for c, v in checks.items() if v[0] == mod]
            if not ids:
                continue
            rs = [results.get(c) for c in ids]
            if all(r and r[0] == "N/A" for r in rs) and not any("DEAD CODE:" in r[1] and CHECKABLE.search(r[1]) for r in rs):
                errors.append(f"profile: '{mod}' applies ({where[0] if where[0].startswith('your answer') else 'the code shows it, e.g. ' + where[0]}), so it can't be N/A as a whole. "
                              "Check its items one by one, or prove the code is unused: N/A with 'DEAD CODE: <proof>'")
    if not prof_path.exists() and level != "quick":
        warns.append("no profile.json next to the ledger: run profile.py first (or say why in the report)")

    # inventory accounting
    inv_path = ledger_path.parent / "inventory.json"
    inv_lines = []
    if inv_path.exists():
        counts = json.loads(inv_path.read_text("utf-8")).get("counts", {})
        for cat, n in counts.items():
            if not n:
                continue
            row = inv_rows.get(cat)
            if not row:
                errors.append(f"INV-{cat}: inventory found {n}, but the ledger has no INV-{cat} row (checked/found)")
                continue
            m = re.match(r"\s*(\d+)\s*/\s*(\d+)", row[0])
            if not m:
                errors.append(f"INV-{cat}: result must be checked/found, e.g. {n}/{n}")
                continue
            done, total = int(m.group(1)), int(m.group(2))
            if total < n:
                errors.append(f"INV-{cat}: says {total} found, but the inventory script found {n}")
            if done < total:
                warns.append(f"INV-{cat}: only {done}/{total} checked ({row[1] or 'no reason given'}): report as partial")
            inv_lines.append((cat, done, max(total, n)))
    else:
        warns.append("no inventory.json next to the ledger: run inventory.py first (or say why in the report)")

    # sweep hits
    sweep_path = ledger_path.parent / "sweep.json"
    sweep_total = sweep_unreviewed = 0
    if sweep_path.exists():
        hits = json.loads(sweep_path.read_text("utf-8")).get("hits", [])
        sweep_total = len(hits)
        for h in hits:
            row = hit_rows.get(h["id"])
            if not row:
                sweep_unreviewed += 1
            else:
                v = row[0].upper()
                if not (v.startswith("FINDING") or v.startswith("RULED OUT")):
                    errors.append(f"{h['id']}: verdict must be FINDING <check ID> or RULED OUT")
                elif v.startswith("FINDING") and not re.search(r"[A-Z0-9]+-\d{2,3}", row[0] + " " + row[1]):
                    errors.append(f"{h['id']}: FINDING must name the check ID it belongs to")
                elif not row[1] or len(row[1]) < 8:
                    errors.append(f"{h['id']}: verdict needs a reason")
        if sweep_unreviewed:
            errors.append(f"sweep: {sweep_unreviewed} of {sweep_total} hits have no verdict (FINDING or RULED OUT)")
    else:
        warns.append("no sweep.json next to the ledger: run sweep.py first (or say why in the report)")

    # hunt: hypotheses tested by attacking the app's own logic (references/hunt.md)
    hunt_stats = None
    if level in ("full", "enterprise"):
        need_n, need_m = (12, 4) if level == "full" else (25, 6)
        methods, proven, proven_new, disproven, untested = set(), 0, 0, 0, 0
        for key, cells in hunt_rows:
            if len(cells) < 5:
                errors.append(f"{key}: hunt rows are | ID | Hypothesis | Method | Result | Evidence |")
                continue
            hyp, meth, resu, evid = cells[1], cells[2].upper().strip("` "), cells[3].upper().strip("` "), " | ".join(cells[4:]).strip()
            if meth not in HUNT_METHODS:
                errors.append(f"{key}: method must be one of {', '.join(sorted(HUNT_METHODS))} (got '{cells[2]}')")
            methods.add(meth)
            if len(hyp) < 10:
                errors.append(f"{key}: write the hypothesis as a full sentence")
            if resu.startswith("PROVEN"):
                proven += 1
                ref = resu[len("PROVEN"):].strip()
                if ref == "NEW":
                    proven_new += 1
                elif not (ref in checks):
                    errors.append(f"{key}: PROVEN must be followed by NEW or an existing check ID (got '{cells[3]}')")
                if not CHECKABLE.search(evid):
                    errors.append(f"{key}: PROVEN needs a proof: a test or script in .vibe-check/proofs/, or the quoted code path")
            elif resu.startswith("DISPROVEN"):
                disproven += 1
                if not CHECKABLE.search(evid):
                    errors.append(f"{key}: DISPROVEN needs what stopped it (file:line, constraint, test)")
            elif resu.startswith("UNTESTED"):
                untested += 1
                if len(evid) < 8:
                    errors.append(f"{key}: UNTESTED needs why, and what would test it")
            else:
                errors.append(f"{key}: result must be PROVEN NEW, PROVEN <check ID>, DISPROVEN or UNTESTED")
        n_fail = sum(1 for v in results.values() if v[0] == "FAIL")
        if len(hunt_rows) < need_n:
            errors.append(f"hunt: {len(hunt_rows)} hypotheses; a {level} check needs at least {need_n} (references/hunt.md)")
        if len(methods & HUNT_METHODS) < need_m:
            errors.append(f"hunt: {len(methods & HUNT_METHODS)} methods used; a {level} check needs at least {need_m}")
        for must in ("INVARIANT", "ABUSE"):
            if hunt_rows and must not in methods:
                errors.append(f"hunt: no {must} hypotheses (required)")
        if n_fail and "VARIANT" not in methods:
            errors.append("hunt: there are confirmed FAILs but no VARIANT hypotheses (search for siblings of each finding)")
        if n_fail >= 2 and "CHAIN" not in methods:
            errors.append("hunt: two or more FAILs but no CHAIN hypotheses (can they combine?)")
        tm = re.search(r"^##\s*Threat model\s*\n((?:\s*[-*].*\n?)+)", text, re.M)
        if not tm or len([l for l in tm.group(1).splitlines() if l.strip()]) < 3:
            errors.append("hunt: the ledger needs a '## Threat model' section with assets, actors, boundaries and entry points")
        hunt_stats = (len(hunt_rows), proven, proven_new, disproven, untested, len(methods & HUNT_METHODS))

    # component versions: each needs a verdict backed by a source opened in this run, or an audit tool
    ver_path = ledger_path.parent / "versions.json"
    ver_total = ver_open = 0
    ver_bad = []
    if ver_path.exists():
        comps = json.loads(ver_path.read_text("utf-8")).get("components", [])
        ver_total = len(comps)
        for c in comps:
            row = ver_rows.get(c["id"])
            if not row:
                ver_open += 1
                continue
            v = row[0].upper().replace("’", "'")
            status = next((s for s in ("CURRENT", "OUTDATED", "EOL", "VULNERABLE", "CAN'T TELL") if v.startswith(s)), None)
            if not status:
                errors.append(f"{c['id']}: verdict must be CURRENT, OUTDATED, EOL, VULNERABLE or CAN'T TELL")
            elif status != "CAN'T TELL" and not SOURCE.search(row[1]):
                errors.append(f"{c['id']} ({c['name']} {c['version']}): {status} needs the source URL opened in this run "
                              "or the audit tool that checked it (no versions from memory)")
            elif len(row[1]) < 8:
                errors.append(f"{c['id']}: verdict needs a reason")
            elif status in ("OUTDATED", "EOL", "VULNERABLE"):
                ver_bad.append(f"{c['id']} {c['name']} {c['version']}: {status}")
        if ver_open:
            errors.append(f"versions: {ver_open} of {ver_total} components have no verdict (V- rows)")
    elif level != "quick":
        warns.append("no versions.json next to the ledger: run versions.py first (or say why in the report)")

    if remaining_only:
        by_mod = {}
        for c in missing:
            by_mod.setdefault(checks[c][0], []).append(c)
        print(f"Level: {level} · remaining: {len(missing)} of {len(required)} required checks")
        for mod in order:
            if mod in by_mod:
                ids = by_mod[mod]
                print(f"  {mod:<20} {len(ids):>3} left: {', '.join(ids[:12])}{' …' if len(ids) > 12 else ''}")
        if sweep_unreviewed:
            print(f"  sweep hits without a verdict: {sweep_unreviewed}")
        if ver_open:
            print(f"  components without a version verdict: {ver_open}")
        return 0 if not missing else 1

    # coverage table
    rows = []
    tot = {"PASS": 0, "FAIL": 0, "N/A": 0, "CAN'T TELL": 0}
    blockers = unresolved = 0
    for mod in order:
        ids = [c for c in required if checks[c][0] == mod]
        if not ids:
            continue
        cnt = {"PASS": 0, "FAIL": 0, "N/A": 0, "CAN'T TELL": 0}
        for c in ids:
            if c in results:
                cnt[results[c][0]] += 1
                if results[c][0] == "FAIL" and checks[c][1] == "🔴":
                    blockers += 1
                if results[c][0] == "CAN'T TELL" and checks[c][1] == "🔴":
                    unresolved += 1
        miss = len(ids) - sum(cnt.values())
        for k in tot:
            tot[k] += cnt[k]
        status = "➖" if cnt["N/A"] == len(ids) else ("❗" if miss == len(ids) else ("◐" if miss or cnt["CAN'T TELL"] else "✅"))
        rows.append((mod, status, len(ids), cnt, miss))
    applicable = tot["PASS"] + tot["FAIL"] + tot["CAN'T TELL"] + len(missing)

    run_date = seed_m.group(1).strip() if seed_m else ""
    res = compute_result(required, results, checks, level, run_date)
    hist_dir = ledger_path.parent / "history"
    diff = compare_with_history(res, hist_dir)
    res["since_last"] = diff
    print_result(res, diff)
    (ledger_path.parent / "results.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
    print(f"## Coverage (counted by coverage.py · level: {level})\n")
    print("| Module | Status | Checks | ✅ Pass | Failed | ➖ N/A | ❓ Can't tell | ❗ Not done |")
    print("|---|---|---|---|---|---|---|---|")
    for mod, status, n, cnt, miss in rows:
        print("| %s | %s | %d | %d | %d | %d | %d | %d |" % (mod, status, n, cnt["PASS"], cnt["FAIL"], cnt["N/A"], cnt[CT], miss))
    print("| **Total** | | **%d** | **%d** | **%d** | **%d** | **%d** | **%d** |" % (len(required), tot["PASS"], tot["FAIL"], tot["N/A"], tot[CT], len(missing)))
    if inv_lines:
        print("\n| Inventory | Checked |\n|---|---|")
        for cat, done, total in inv_lines:
            print(f"| {cat} | {done}/{total}{'' if done >= total else ' ◐'} |")
    if sweep_path.exists():
        print(f"\nSweep: {sweep_total} hits, {sweep_total - sweep_unreviewed} reviewed.")
    if hunt_stats:
        n, pr, new, dis, unt, nm = hunt_stats
        print(f"\nHunt: {n} hypotheses ({nm} methods): {pr} proven ({new} new, not in any checklist), {dis} disproven, {unt} untested.")
    if ver_path.exists():
        print(f"\nVersions: {ver_total} components, {ver_total - ver_open} checked, {len(ver_bad)} outdated / end-of-life / vulnerable.")
        for b in ver_bad:
            print(f"  - {b}")
    stds = load_standards()
    if stds and not remaining_only:
        print("\n## Standards (how this audit's checks came out for each item; not a certification)\n")
        print("| Standard | ✅ | ❌ | ◐ | ➖ | Items that failed |")
        print("|---|---|---|---|---|---|")
        only_if = {"Mobile": (["mobile", "android", "ios", "mobile-frameworks", "mobile-data"], "no mobile app"), "LLM": (["ai-features", "ai-agents"], "no AI features")}
        for title, items in stds:
            gate = next((v for k, v in only_if.items() if k in title), None)
            if gate and all(status_of(c, results, checks) == "NA" for c in required if checks[c][0] in gate[0]):
                print(f"| {title} | ➖ | ➖ | ➖ | ➖ | doesn't apply ({gate[1]}) |")
                continue
            tally = {"ok": 0, "fail": 0, "part": 0, "na": 0}
            failed = []
            for iid, name, ids, human in items:
                rs = [results[c][0] for c in ids if c in results]
                if any(r == "FAIL" for r in rs):
                    tally["fail"] += 1; failed.append(iid)
                elif rs and all(r == "N/A" for r in rs) and len(rs) == len(ids):
                    tally["na"] += 1
                elif rs and len(rs) == len(ids) and all(r in ("PASS", "N/A") for r in rs) and not human:
                    tally["ok"] += 1
                else:
                    tally["part"] += 1
            print(f"| {title} | {tally['ok']} | {tally['fail']} | {tally['part']} | {tally['na']} | {', '.join(failed) or '-'} |")
        print("\n◐ = some mapped checks couldn't be confirmed, weren't done, or need a human specialist (see references/standards.md).")
    print(f"\nScore card: vibe-check: {res['verdict']} · Score {res['score']}/100 · {res['totals']['passed']}/{res['totals']['apply']} checks · "
          f"<blocker headings in the report> blockers ({res['totals']['blockers']} checks) · {level.title()} check · {run_date or 'date'}")

    if report_path is not None:
        rep_text = report_path.read_text("utf-8") if report_path.exists() else ""
        if not rep_text:
            errors.append(f"REPORT: {report_path} not found")
        else:
            seen_rows = 0
            for mod, status, n, cnt, miss in rows:
                m = re.search(r"^\|\s*\**%s\**\s*\|[^|\n]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|" % re.escape(mod), rep_text, re.M)
                if not m:
                    errors.append(f"REPORT: the coverage table has no row for {mod} (paste the table coverage.py printed)")
                    continue
                seen_rows += 1
                real = [n, cnt["PASS"], cnt["FAIL"], cnt["N/A"], cnt[CT], miss]
                got = [int(x) for x in m.groups()]
                if got != real:
                    errors.append(f"REPORT: coverage row for {mod} says {got}, the ledger says {real}")
            T = res["totals"]
            sc = re.search(r"vibe-check:\s*\S+[^·\n]*·\s*Score\s*(\d+)\s*/\s*100\s*·\s*(\d+)\s*/\s*(\d+)\s*checks\s*·\s*\d+\s*blockers?\s*\((\d+)\s*checks?\)", rep_text)
            if not sc:
                errors.append("REPORT: no score card line ('vibe-check: … · Score N/100 · passed/applicable checks · N blockers (M checks)')")
            elif [int(x) for x in sc.groups()] != [res["score"], T["passed"], T["apply"], T["blockers"]]:
                errors.append(f"REPORT: the score card says Score {sc.group(1)}, {sc.group(2)}/{sc.group(3)} checks and {sc.group(4)} blockers; "
                              f"the ledger says Score {res['score']}, {T['passed']}/{T['apply']} and {T['blockers']}")
            hs = re.search(r"Score\s*(\d+)\s*/\s*100", rep_text)
            if hs and int(hs.group(1)) != res["score"]:
                errors.append(f"REPORT: the first score in the report is {hs.group(1)}/100; the ledger says {res['score']}/100")
            ck = re.search(r"Checked\**\s*\|\s*\**(\d+)\s*of\s*(\d+)", rep_text)
            if not ck:
                errors.append("REPORT: no totals table ('| **Checked** | **N of M** |' pasted from coverage.py)")
            elif [int(x) for x in ck.groups()] != [T["checked"], T["apply"]]:
                errors.append(f"REPORT: totals say checked {ck.group(1)} of {ck.group(2)}; the ledger says {T['checked']} of {T['apply']}")
            # every check with its evidence, written by the script into the report
            write_appendix(report_path, build_appendix(required, results, checks))
            rep_text = report_path.read_text("utf-8")
            # questions: every ❓ the user can answer was asked (or they chose to skip), before the report
            # v3.9.1: ask only what matters: the 🔴/🟡 questions first (up to 15); everything else is listed in the report
            unasked = [c for c in required if status_of(c, results, checks) == "ASK" and ask_kind(c, results) == "ask" and c not in ans_text]
            asked_n = sum(1 for line in ans_text.splitlines() if re.match(r"^\|\s*(?:BS-\d{2}|[A-Z0-9]+-\d{3})\s*\|", line))
            skipped_all = bool(re.search(r"skip(?:ped)? the rest|skipped: unattended", ans_text, re.I))
            important = [c for c in unasked if checks[c][1] in ("🔴", "🟡")]
            if important and not skipped_all and asked_n < 15:
                errors.append(f"REPORT: {len(important)} 🔴/🟡 question(s) weren't asked ({', '.join(important[:6])}…): ask the most serious "
                              f"first, as choices, up to 15 in all ({asked_n} so far), and record each answer or skip in .vibe-check/answers.md")
            qsec = re.search(r"^##[^\n]*Questions for you[^\n]*\n(.*?)(?=^## |\Z)", rep_text, re.M | re.S)
            not_listed = [c for c in unasked if not qsec or c not in qsec.group(1)]
            if not_listed:
                errors.append(f"REPORT: {len(not_listed)} open question(s) aren't listed under '❓ Questions for you' "
                              f"({', '.join(not_listed[:6])}…): every question not asked goes there, so none is lost")
            # v3.7: the report says how much was redone, carried over and settled by script
            if savings_line(T) not in rep_text:
                errors.append(f"REPORT: add this line under the Checks table, exactly as coverage.py prints it: '{savings_line(T)}'")
            # check-yourself items: all listed in the report, grouped by place
            missing_chk = [c for c in required if status_of(c, results, checks) == "ASK" and ask_kind(c, results) == "check" and c not in rep_text]
            if missing_chk:
                errors.append(f"REPORT: {len(missing_chk)} check-yourself item(s) aren't in the report ({', '.join(missing_chk[:6])}…): "
                              "paste the list from 'coverage.py --check-list' into '🖥️ Check these yourself'")
            # blockers: one heading per real problem, each with a prompt (or steps only the user can do)
            sec = re.search(r"^##[^\n]*Blockers[^\n]*\n(.*?)(?=^## )", rep_text, re.M | re.S)
            heads = re.findall(r"^#{3,4}\s*\d+\.", sec.group(1), re.M) if sec else []
            if T["blockers"] and not heads:
                errors.append("REPORT: the Blockers section needs one '### 1. <title>' heading per real problem")
            if sec and heads:
                blocks = re.split(r"^#{3,4}\s*\d+\.", sec.group(1), flags=re.M)[1:]
                missing_p = [str(i + 1) for i, b in enumerate(blocks) if "Prompt to fix it" not in b and "Steps for you" not in b]
                if missing_p:
                    errors.append(f"REPORT: blocker(s) {', '.join(missing_p)} have no 'Prompt to fix it' (or 'Steps for you' when only the user can fix it)")
            pb = re.search(r"·\s*(\d+)\s*blockers?\s*\((\d+)\s*checks?\)", rep_text)
            if T["blockers"] and not pb:
                errors.append("REPORT: the score card must say '· N blockers (M checks) ·': N problems, M blocker checks")
            elif pb and (int(pb.group(2)) != T["blockers"] or (heads and int(pb.group(1)) != len(heads))):
                errors.append(f"REPORT: the score card says {pb.group(1)} blockers ({pb.group(2)} checks); the report has {len(heads)} blocker "
                              f"headings and the ledger {T['blockers']} blocker checks")
            # the audit never changes the user's code: compare with the fingerprint profile.py took at the start
            changed = changed_since_fingerprint(root, ledger_path.parent)
            if changed:
                log = (ledger_path.parent / "fix-log.md")
                logged = log.read_text("utf-8") if log.exists() else ""
                unlogged = [f for f in changed if f not in logged]
                if unlogged:
                    errors.append(f"REPORT: {len(unlogged)} project file(s) changed since the audit started and aren't in an approved fix "
                                  f"card in .vibe-check/fix-log.md: {', '.join(unlogged[:8])}. An audit never changes the user's code: "
                                  "undo these changes and tell the user what happened")
            # secret guard: nothing that leaves the project may hold a full secret (same patterns as sweep.py)
            for _shared in [report_path, ledger_path.parent / "summary.md", ledger_path]:
                for _line_no, _kind, _title in find_secrets(_shared):
                    errors.append(f"REPORT: {_shared.name}:{_line_no} looks like a full {_title}. Mask it: first 4 characters "
                                  "and where it is (e.g. `sk_l…` in src/lib/stripe.ts:3)")
            if diff and "Since last check" not in rep_text:
                errors.append("REPORT: there is an earlier run in .vibe-check/history/, so the report needs the 'Since last check' line")
            if not errors:
                print(f"\nREPORT VERIFIED: {report_path} matches the ledger ({seen_rows} coverage rows and the score card).")

    if part_file is not None:
        # v3.9.1: a helper checks only its own rows before finishing, so no separate tidy-up pass is needed
        try:
            part_text = part_file.read_text("utf-8")
        except OSError:
            print(f"No file at {part_file}"); return 2
        part_ids = set(re.findall(r"^\|\s*`?((?:BS-\d{2}|[A-Z0-9]+-\d{3}|[A-Z]+-[\w*-]+))`?\s*\|", part_text, re.M))
        mine = [e for e in errors if e.split(":", 1)[0].strip() in part_ids]
        for e in mine:
            print("GAP:", e)
        print(f"\nPART OK: {part_file.name} ({len(part_ids)} rows) has no problems." if not mine
              else f"\nPART: {len(mine)} problem(s) in {part_file.name}. Fix them before you finish.")
        return 0 if not mine else 1
    for w in warns:
        print("warning:", w)
    if missing:
        errors.insert(0, f"{len(missing)} required checks have no result: {', '.join(missing[:15])}{' …' if len(missing) > 15 else ''}"
                         " (run with --remaining)")
    for e in errors:
        print("GAP:", e)
    print("\nCOMPLETE: every required check has a result." if not errors else f"\nINCOMPLETE: {len(errors)} gap(s). Fix them before writing the report.")
    if want_save:
        if errors:
            print("not saved to history: the count isn't complete")
        else:
            hist_dir.mkdir(exist_ok=True)
            from datetime import datetime
            name = datetime.now().strftime("%Y-%m-%d-%H%M%S-%f") + ".json"
            carry = {"evidence": {}, "files": {}, "items": item_hashes(), "profile": profile_hash(ledger_path.parent)}
            for c in required:
                if c in results and results[c][0] in ("PASS", "N/A"):
                    ev = results[c][1]
                    cm = CARRY_RX.match(ev)
                    ev = cm.group(3) if cm else ev
                    if re.match(r"^\s*AUTO\b", ev):
                        continue          # autocheck.py settles these again every run (cheap)
                    carry["evidence"][c] = [results[c][0], ev]
                    for rel in (cited_files(ev, root) or []):
                        carry["files"][rel] = file_hash(root, rel)
            res["carry"] = carry
            (hist_dir / name).write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
            print(f"saved to history: {hist_dir / name} (the next run compares with it)")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
