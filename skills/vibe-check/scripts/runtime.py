#!/usr/bin/env python3
"""runtime.py: test the running app (local or approved staging), after the user says yes.

    python3 runtime.py [PROJECT_DIR] --plan
        Write .vibe-check/runtime/runtime.json from the inventory: routes and endpoints to test, accounts to fill in.
    python3 runtime.py [PROJECT_DIR] --run authz|api|webhooks|browser|all --consent
        Run the tests. Needs 'RUNTIME: yes' in .vibe-check/answers.md, and a local target (localhost, 127.0.0.1,
        *.localhost, *.test) or 'RUNTIME: target <host>: yes' for an approved staging host.
    python3 runtime.py [PROJECT_DIR] --setup-browser --consent
        Install Playwright and Chromium into .vibe-check/runtime/ (needs 'RUNTIME: playwright: yes'; about 300-500 MB).
        Never touches the project's own package.json.

What it tests:
  authz     every case in runtime.json as signed out, user A, user B and admin: who got in (LIVE-002/003/004, SEC-015),
            and whether responses carry password hashes, tokens or secrets (SEC-055)
  api       a small burst on sign-in (LIVE-006, SEC-007), malformed input and unknown routes leaking errors (LIVE-007),
            CORS (SEC-037), security headers (SEC-046)
  webhooks  unsigned and wrongly signed payment webhooks are refused (FIN-003)
  browser   the flows and pages in runtime.json in a real browser: steps work, no page errors or 5xx (LIVE-012),
            pages fit a phone screen (LIVE-013), the test-mode payment flow completes (LIVE-014)

Safety, enforced here: production is never a target; bursts are small (12 requests); every request has a 10-second
timeout; test account tokens live only in runtime.json (git-ignored) and are never printed. Python 3.8+, standard library.
"""
import json
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

TIMEOUT = 10
BURST = 12
LOCAL = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|[\w.-]+\.localhost|[\w.-]+\.test|0\.0\.0\.0)$", re.I)
LEAK = re.compile(r"Traceback \(most recent call last\)|\bat [\w.$<>]+ \([^)]*:\d+:\d+\)|SQLSTATE|PrismaClient\w*Error|SequelizeDatabaseError|"
                  r"ORA-\d{5}|\"stack\"\s*:\s*\"|node_modules/|\b(?:TypeError|ReferenceError|SyntaxError): |Exception in thread|"
                  r"pg_catalog|syntax error at or near")
SENSITIVE_KEYS = re.compile(r'"(password|password_hash|passwordHash|hashed_password|secret|api_key|apiKey|access_token|refresh_token|'
                            r'service_role|private_key|ssn|card_number)"\s*:', re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def request(base, method, path, account=None, body=None, headers=None, raw=None):
    """-> (status, headers dict, body text). Never follows redirects (a redirect to sign-in counts as refused)."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    h = {"User-Agent": "vibe-check-runtime", "Accept": "application/json, text/html"}
    acct = account or {}
    h.update(acct.get("headers", {}))
    if acct.get("cookies"):
        h["Cookie"] = acct["cookies"]
    h.update(headers or {})
    data = None
    if raw is not None:
        data = raw.encode()
        h.setdefault("Content-Type", "application/json")
    elif body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=h)
    try:
        with OPENER.open(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            txt = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            txt = ""
        return e.code, dict(e.headers or {}), txt
    except (urllib.error.URLError, OSError) as e:
        return 0, {}, str(e)


class Results:
    def __init__(self):
        self.items = []

    def add(self, slug, checks, status, summary, detail=None):
        self.items.append({"id": f"runtime:{slug}", "checks": checks, "status": status, "summary": summary[:300], "detail": detail or []})


def allowed_target(base, answers):
    host = urlparse(base).hostname or ""
    if LOCAL.match(host):
        return True, host
    ok = re.search(r"^\s*[-*]?\s*RUNTIME:\s*target\s+" + re.escape(host) + r"\s*:?\s*yes\b", answers, re.M | re.I)
    return bool(ok), host


# ---- tests ----
def t_authz(cfg, res):
    base, accts = cfg["base_url"], cfg.get("accounts", {})
    cases = cfg.get("authz", [])
    if not cases:
        res.add("authz", ["LIVE-002"], "info", "no authz cases in runtime.json: list each route with its owner and who may use it"); return
    viol = {"LIVE-002": [], "LIVE-003": [], "LIVE-004": []}
    tried, exposed = 0, []
    for c in cases:
        allow = set(c.get("allow", []))
        for who in ("anon", "a", "b", "admin"):
            if who != "anon" and who not in accts:
                continue
            st, _, body = request(base, c.get("method", "GET"), c["path"], accts.get(who, {}), c.get("body"))
            tried += 1
            if 200 <= st < 300:
                if SENSITIVE_KEYS.search(body or ""):
                    exposed.append(f"{c['method'] if 'method' in c else 'GET'} {c['path']} as {who}: {SENSITIVE_KEYS.search(body).group(1)}")
                if who in allow:
                    continue
                line = f"{c.get('method', 'GET')} {c['path']} let {'a signed-out visitor' if who == 'anon' else 'user ' + who.upper() if who in ('a', 'b') else who} in ({st})"
                if who == "anon":
                    viol["LIVE-004"].append(line)
                elif allow == {"admin"} or (c.get("role") == "admin"):
                    viol["LIVE-003"].append(line)
                else:
                    viol["LIVE-002"].append(line)
    labels = {"LIVE-002": ("authz-other-users", ["LIVE-002", "SEC-015"], "user B reached user A's data"),
              "LIVE-003": ("authz-roles", ["LIVE-003"], "a normal user reached admin functions"),
              "LIVE-004": ("authz-signed-out", ["LIVE-004"], "signed-out visitors got in")}
    for k, (slug, checks, what) in labels.items():
        v = viol[k]
        res.add(slug, checks, "fail" if v else "pass",
                f"{len(v)} case(s) where {what}: {'; '.join(v[:4])}" if v else f"refused correctly in all {len(cases)} case(s)", v)
    res.add("response-fields", ["SEC-055"], "fail" if exposed else "pass",
            f"responses carrying sensitive fields: {'; '.join(exposed[:4])}" if exposed else f"no password, token or secret fields in {tried} responses", exposed)


def t_api(cfg, res):
    base, accts = cfg["base_url"], cfg.get("accounts", {})
    login = cfg.get("login")
    if login:
        codes, limited = [], False
        for _ in range(BURST):
            st, _, body = request(base, login.get("method", "POST"), login["path"], None, login.get("body"))
            codes.append(st)
            if st == 429 or re.search(r"too many|rate limit|locked|try again later", body or "", re.I):
                limited = True
                break
        res.add("rate-limit-login", ["LIVE-006", "SEC-007"], "pass" if limited else "fail",
                f"sign-in limited after {len(codes)} attempts" if limited else
                f"{BURST} wrong sign-ins in a row were all accepted for checking (codes {sorted(set(codes))}); no limit triggered (if limits are off only in local development, test on staging)")
    leaks = []
    targets = [e for e in cfg.get("endpoints", []) if e.get("method", "GET").upper() in ("POST", "PUT", "PATCH")][:20]
    for e in targets:
        st, _, body = request(base, e["method"], e["path"], accts.get("a"), raw='{"vibe_check": ')
        m = LEAK.search(body or "")
        if m:
            leaks.append(f"{e['method']} {e['path']} ({st}): {m.group(0)[:40]}")
    st, _, body = request(base, "GET", "/__vibe_check_missing_route__")
    m = LEAK.search(body or "")
    if m:
        leaks.append(f"unknown route ({st}): {m.group(0)[:40]}")
    res.add("error-leaks", ["LIVE-007"], "fail" if leaks else "pass",
            f"errors show internals: {'; '.join(leaks[:4])}" if leaks else f"no stack traces or database errors in {len(targets) + 1} malformed or unknown requests", leaks)
    evil = "https://vibe-check-test.example"
    st, h, _ = request(base, "GET", cfg.get("cors_path", "/"), accts.get("a"), headers={"Origin": evil})
    hl = {k.lower(): v for k, v in h.items()}
    aco, acc = hl.get("access-control-allow-origin"), (hl.get("access-control-allow-credentials") or "").lower() == "true"
    bad = (aco == evil and acc) or (aco == "*" and acc)
    res.add("cors", ["SEC-037"], "fail" if bad else "pass",
            f"any website can read signed-in responses: Access-Control-Allow-Origin {aco} with credentials" if bad else
            f"a foreign origin isn't trusted with credentials (Access-Control-Allow-Origin: {aco or 'not set'})")
    st, h, _ = request(base, "GET", "/")
    hl = {k.lower(): v for k, v in h.items()}
    missing = [n for n, ok in (("Content-Security-Policy", "content-security-policy" in hl),
                               ("X-Content-Type-Options", "x-content-type-options" in hl),
                               ("frame protection", "x-frame-options" in hl or "frame-ancestors" in hl.get("content-security-policy", "")))
               if not ok]
    local = LOCAL.match(urlparse(base).hostname or "") is not None
    res.add("security-headers", ["SEC-046"], ("check" if local else "fail") if missing else "pass",
            (f"missing on {'the local server' if local else 'the target'}: {', '.join(missing)}" + ("; headers set by the host only show on staging or production" if local else ""))
            if missing else "Content-Security-Policy, X-Content-Type-Options and frame protection are set")


def t_webhooks(cfg, res):
    base = cfg["base_url"]
    hooks = cfg.get("webhooks", [])
    if not hooks:
        res.add("webhooks", ["FIN-003"], "info", "no webhooks in runtime.json"); return
    bad = []
    for wh in hooks:
        payload = {"id": "evt_vibe_check_test", "type": "checkout.session.completed", "data": {"object": {"id": "cs_vibe_check_test"}}}
        st1, _, _ = request(base, "POST", wh["path"], None, payload)
        st2, _, _ = request(base, "POST", wh["path"], None, payload, headers={"Stripe-Signature": "t=1,v1=00", "X-Signature": "invalid"})
        for st, kind in ((st1, "an unsigned"), (st2, "a wrongly signed")):
            if 200 <= st < 300:
                bad.append(f"{wh['path']} accepted {kind} event ({st})")
    res.add("webhook-signatures", ["FIN-003"], "fail" if bad else "pass",
            f"{'; '.join(bad[:4])}" if bad else f"unsigned and wrongly signed events refused by {len(hooks)} webhook(s)", bad)


BROWSER_JS = r"""
import { chromium } from 'playwright';
import fs from 'fs';
const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = { flows: [], pages: [] };
let browser;
try { browser = await chromium.launch(); } catch (e) { browser = await chromium.launch({ channel: 'chrome' }); }  // fall back to the user's installed Chrome
async function newPage(w, h) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h } });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push('page error: ' + String(e.message).slice(0, 120)));
  page.on('console', m => { if (m.type() === 'error' && !/favicon/i.test((m.location() || {}).url || '')) errs.push('console: ' + m.text().slice(0, 120)); });
  page.on('response', r => { if (r.status() >= 500) errs.push(r.status() + ' ' + r.url().slice(0, 120)); });
  return { ctx, page, errs };
}
const base = cfg.base_url.replace(/\/$/, '');
for (const f of cfg.flows || []) {
  const { ctx, page, errs } = await newPage(1280, 800);
  let failed = null;
  try {
    for (const s of f.steps) {
      if (s.goto) await page.goto(base + s.goto, { timeout: 15000 });
      if (s.fill) await page.fill(s.fill[0], s.fill[1], { timeout: 10000 });
      if (s.click) await page.click(s.click, { timeout: 10000 });
      if (s.expect_url) await page.waitForURL('**' + s.expect_url + '**', { timeout: 15000 });
      if (s.expect_text) await page.getByText(s.expect_text).first().waitFor({ timeout: 15000 });
    }
  } catch (e) { failed = String(e.message).split('\n')[0].slice(0, 160); }
  out.flows.push({ name: f.name, payment: !!f.payment, failed, errors: errs });
  await ctx.close();
}
for (const p of cfg.pages || ['/']) {
  const { ctx, page, errs } = await newPage(375, 812);
  let overflow = false;
  try {
    await page.goto(base + p, { timeout: 15000 });
    overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  } catch (e) { errs.push('could not open: ' + String(e.message).split('\n')[0].slice(0, 120)); }
  out.pages.push({ path: p, overflow, errors: errs });
  await ctx.close();
}
await browser.close();
console.log(JSON.stringify(out));
"""


def t_browser(cfg, res, rt_dir):
    pw = rt_dir / "node_modules" / "playwright"
    if not pw.exists() or not shutil.which("node"):
        res.add("browser", ["LIVE-012"], "info", "Playwright isn't set up: ask, then run runtime.py --setup-browser --consent"); return
    (rt_dir / "flows.mjs").write_text(BROWSER_JS, "utf-8")
    p = subprocess.run(["node", str(rt_dir / "flows.mjs"), str(rt_dir / "runtime.json")], capture_output=True, text=True, timeout=900, cwd=rt_dir)
    try:
        out = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        res.add("browser", ["LIVE-012"], "info", f"the browser run didn't finish: {p.stderr.strip()[:160]}"); return
    flows = [f for f in out["flows"] if not f["payment"]]
    pay = [f for f in out["flows"] if f["payment"]]
    broken = [f"{f['name']}: {f['failed'] or '; '.join(f['errors'][:2])}" for f in flows if f["failed"] or f["errors"]]
    if flows:
        res.add("flows", ["LIVE-012"], "fail" if broken else "pass",
                f"{len(broken)} of {len(flows)} flows broke: {'; '.join(broken[:3])}" if broken else f"all {len(flows)} flows completed with no page errors or 5xx", broken)
    over = [p_["path"] for p_ in out["pages"] if p_["overflow"]]
    res.add("phone-width", ["LIVE-013"], "fail" if over else "pass",
            f"wider than a phone screen (375px): {', '.join(over)}" if over else f"all {len(out['pages'])} pages fit a 375px phone screen")
    if pay:
        pb = [f"{f['name']}: {f['failed'] or '; '.join(f['errors'][:2])}" for f in pay if f["failed"] or f["errors"]]
        res.add("payment-flow", ["LIVE-014"], "fail" if pb else "pass",
                f"the test-mode payment flow broke: {'; '.join(pb[:2])}" if pb else "the test-mode payment flow completed")


def plan(root, rt_dir):
    inv = {}
    try:
        inv = json.loads((root / ".vibe-check" / "inventory.json").read_text("utf-8")).get("items", {})
    except (OSError, ValueError):
        pass
    endpoints = []
    for cat, items in inv.items():
        if not re.search(r"route|endpoint|api|function", cat, re.I):
            continue
        for it in items:
            m = re.search(r"\b(GET|POST|PUT|PATCH|DELETE)\b\s+(/[\w/{}:.\[\]-]*)", it)
            m2 = m or re.search(r"(/api/[\w/{}:.\[\]-]*)", it)
            if m:
                endpoints.append({"method": m.group(1), "path": m.group(2)})
            elif m2:
                endpoints.append({"method": "GET", "path": m2.group(1)})
    seen, uniq = set(), []
    for e in endpoints:
        k = (e["method"], e["path"])
        if k not in seen:
            seen.add(k); uniq.append(e)
    tpl = {
        "base_url": "http://localhost:3000",
        "accounts": {"a": {"headers": {"Authorization": "Bearer <user A's test token>"}}, "b": {"headers": {"Authorization": "Bearer <user B's test token>"}},
                     "admin": {"headers": {"Authorization": "Bearer <admin test token, or remove>"}}},
        "authz": [{"method": e["method"], "path": e["path"].replace("{id}", "<an ID owned by A>"), "owner": "a", "allow": ["a", "admin"]} for e in uniq[:60]],
        "login": {"method": "POST", "path": "/api/auth/login", "body": {"email": "a@test.local", "password": "wrong-password-for-test"}},
        "endpoints": uniq[:60],
        "webhooks": [{"path": "/api/webhooks/stripe", "provider": "stripe"}],
        "flows": [{"name": "sign in", "steps": [{"goto": "/login"}, {"fill": ["input[type=email]", "a@test.local"]},
                                               {"fill": ["input[type=password]", "<test password>"]}, {"click": "button[type=submit]"}, {"expect_url": "/"}]}],
        "pages": ["/", "/login"],
        "_notes": "Fill in from the code: real paths, IDs owned by user A, who may use each route (allow), admin-only routes (allow: [admin]). "
                  "Tokens are for local test accounts only; this file is git-ignored. Remove what doesn't exist."}
    rt_dir.mkdir(parents=True, exist_ok=True)
    f = rt_dir / "runtime.json"
    if f.exists():
        print(f"runtime.json already exists; not overwritten: {f}"); return 0
    f.write_text(json.dumps(tpl, indent=1) + "\n", "utf-8")
    print(f"runtime: plan written to {f} with {len(uniq)} endpoint(s) from the inventory. Fill in the accounts, owners and allow lists.")
    return 0


def setup_browser(rt_dir):
    if not shutil.which("npm"):
        print("npm isn't installed: Playwright can't be set up here."); return 1
    rt_dir.mkdir(parents=True, exist_ok=True)
    if not (rt_dir / "package.json").exists():
        (rt_dir / "package.json").write_text('{"name": "vibe-check-runtime", "private": true, "type": "module"}\n', "utf-8")
    r1 = subprocess.run(["npm", "install", "--prefix", str(rt_dir), "--no-save", "--no-audit", "--no-fund", "playwright@1"], capture_output=True, text=True, timeout=900)
    if r1.returncode != 0:
        print("Playwright install failed:", r1.stderr.strip()[-300:]); return 1
    r2 = subprocess.run([str(rt_dir / "node_modules" / ".bin" / "playwright"), "install", "chromium"], capture_output=True, text=True, timeout=1800)
    if r2.returncode == 0:
        print("runtime: Playwright and Chromium installed in .vibe-check/runtime/"); return 0
    if any(shutil.which(c) for c in ("google-chrome", "google-chrome-stable", "chrome")) or Path("/Applications/Google Chrome.app").exists():
        print("runtime: Playwright installed; Chromium couldn't be downloaded, so browser tests will use your installed Google Chrome"); return 0
    print("Chromium install failed and Google Chrome isn't installed: " + r2.stderr.strip()[-300:]); return 1


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip()); return 0 if argv else 2
    what = None
    if "--run" in argv:
        i = argv.index("--run"); what = argv[i + 1]; del argv[i:i + 2]
    consent = "--consent" in argv
    rest = [a for a in argv if not a.startswith("--")]
    root = Path(rest[0] if rest else ".").resolve()
    vc = root / ".vibe-check"
    rt_dir = vc / "runtime"
    answers = (vc / "answers.md").read_text("utf-8") if (vc / "answers.md").exists() else ""
    if "--plan" in argv:
        return plan(root, rt_dir)
    if "--setup-browser" in argv:
        if not consent or not re.search(r"^\s*[-*]?\s*RUNTIME:\s*playwright\s*:?\s*yes\b", answers, re.M | re.I):
            print("NOT RUN: installing Playwright (about 300-500 MB) needs the user's yes: write 'RUNTIME: playwright: yes' in .vibe-check/answers.md")
            return 1
        return setup_browser(rt_dir)
    if what not in ("authz", "api", "webhooks", "browser", "all"):
        print("Use --plan, --setup-browser, or --run authz|api|webhooks|browser|all"); return 2
    if not consent or not re.search(r"^\s*[-*]?\s*RUNTIME:\s*yes\b", answers, re.M | re.I):
        print("NOT RUN: testing the running app needs the user's yes: write 'RUNTIME: yes' in .vibe-check/answers.md, then use --consent")
        return 1
    try:
        cfg = json.loads((rt_dir / "runtime.json").read_text("utf-8"))
    except (OSError, ValueError) as e:
        print(f"No usable .vibe-check/runtime/runtime.json ({e}): run --plan and fill it in"); return 1
    ok, host = allowed_target(cfg.get("base_url", ""), answers)
    if not ok:
        print(f"REFUSED: {host} isn't local. Runtime tests never run against production; for a staging host, ask and write "
              f"'RUNTIME: target {host}: yes' in .vibe-check/answers.md")
        return 1
    st, _, err = request(cfg["base_url"], "GET", "/")
    if st == 0:
        print(f"The app isn't reachable at {cfg['base_url']} ({err[:120]}). Start it first (for example npm run dev)."); return 1
    res = Results()
    t0 = time.time()
    for name, fn in (("authz", t_authz), ("api", t_api), ("webhooks", t_webhooks)):
        if what in (name, "all"):
            fn(cfg, res)
    if what in ("browser", "all"):
        t_browser(cfg, res, rt_dir)
    path = rt_dir / "results.json"
    old = {}
    if path.exists():
        try:
            old = {r["id"]: r for r in json.loads(path.read_text("utf-8")).get("results", [])}
        except ValueError:
            old = {}
    for r in res.items:
        old[r["id"]] = r
    data = {"consent": True, "target": host, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "results": list(old.values())}
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", "utf-8")
    icon = {"pass": "✅", "fail": "❌", "check": "❓", "info": "➖"}
    lines = ["# Runtime tests", "", f"Target: {host} · {data['time']}. Quote a result exactly as evidence: `RUN: <id> → <summary>`.", "",
             "| | Result id | Checks | Summary |", "|---|---|---|---|"]
    lines += [f"| {icon[r['status']]} | `{r['id']}` | {', '.join(r['checks'])} | {r['summary']} |" for r in data["results"]]
    (rt_dir / "summary.md").write_text("\n".join(lines) + "\n", "utf-8")
    fails = sum(1 for r in res.items if r["status"] == "fail")
    print(f"runtime: {len(res.items)} result(s), {fails} failing, in {time.time() - t0:.0f}s -> .vibe-check/runtime/summary.md")
    for r in res.items:
        print(f"  {r['status']:5} {r['id']}: {r['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
