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
  Every count also writes .vibe-check/results.json (score, band, totals, areas, every check's status).
Exit code 0 = complete, 1 = gaps found. Python 3.8+, standard library only.
"""
from __future__ import annotations

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
    ("Security", ["security", "platforms", "supply-chain", "vulnerabilities", "cloud-infra", "desktop-extensions", "hunt", "live-tests"]),
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
                   "check_places": len(check_groups(required, results, checks))},
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
    print("| Area | Score | Passed | ❌ Must fix | ⚠️ Should fix | ❓ Your answer |\n|---|---|---|---|---|---|")
    for a in res["areas"]:
        if not a["applies"]:
            print(f"| {a['area']} | ➖ doesn't apply | | | | |")
            continue
        dash = lambda n, s: f"{s} {n}" if n else "—"
        print(f"| {a['area']} | `{bar(a['score'])}` {a['score']} | {a['passed']}/{a['applicable']} | {dash(a['blockers'], '❌')} | "
              f"{dash(a['should'], '⚠️')} | {dash(a['ask'], '❓')} |")
    print()



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


def sample_ids(results, checks, seed: str):
    """Deterministic re-check sample: every 🔴 FAIL (up to 13) plus 12 PASS rows, picked by a hash of the ledger date."""
    import hashlib
    h = lambda c: hashlib.sha256((seed + c).encode()).hexdigest()
    fails = sorted([c for c, r in results.items() if r[0] == "FAIL" and checks.get(c, ("", ""))[1] == "🔴"], key=h)[:13]
    passes = sorted([c for c, r in results.items() if r[0] == "PASS"], key=h)[:12]
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
    report_path = None
    if "--verify-report" in argv:
        i = argv.index("--verify-report"); report_path = Path(argv[i + 1]); del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    ledger_path = Path(args[0] if args else ".vibe-check/ledger.md")
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
        m = re.search(r"^\s*Level:\s*\**\s*(quick|full|launch|enterprise)", text, re.I | re.M)
        level = (m.group(1).lower() if m else "full")
    level = "full" if level == "launch" else level

    order, checks, prefixes = load_checklist()
    errors, warns = [], []
    ans_text, answered, adds = load_answers(ledger_path.parent)
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

    sample = sample_ids(results, checks, seed) if level in ("full", "enterprise") else []
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
    for c, v in results.items():
        if v[0] == "CAN'T TELL" and ask_kind(c, results) == "check":
            errors.extend(check_problems(c, v[1], have_sql, db_answer))
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
        only_if = {"Mobile": (["mobile"], "no mobile app"), "LLM": (["ai-features", "ai-agents"], "no AI features")}
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
            unasked = [c for c in required if status_of(c, results, checks) == "ASK" and ask_kind(c, results) == "ask" and c not in ans_text]
            if unasked:
                errors.append(f"REPORT: {len(unasked)} question(s) weren't asked ({', '.join(unasked[:6])}…): ask them as choices before the "
                              "report and record each answer, or that the user skipped it, in .vibe-check/answers.md")
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
            (hist_dir / name).write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
            print(f"saved to history: {hist_dir / name} (the next run compares with it)")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
