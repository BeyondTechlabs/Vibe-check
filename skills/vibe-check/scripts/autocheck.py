#!/usr/bin/env python3
"""autocheck.py: settle the checks a script can decide for certain, before any helper starts.

    python3 autocheck.py [PROJECT_DIR]      -> .vibe-check/ledger.d/01-auto.md

Each rule answers one check only when the answer is certain from the files alone (a lockfile is
missing, there is no README, no CI config at all...). Anything that needs judgement is left to the
helpers. Rows start with `AUTO:`, and coverage.py re-runs the rule when it counts, so an AUTO row
can't be typed by hand or go stale. Read-only; nothing is sent anywhere. Python 3.8+, standard library only.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "poetry.lock", "Pipfile.lock",
             "uv.lock", "Gemfile.lock", "composer.lock", "Cargo.lock", "go.sum", "pubspec.lock"]
MANIFESTS = {"package.json": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"],
             "pyproject.toml": ["poetry.lock", "uv.lock", "requirements.txt", "Pipfile.lock"],
             "Pipfile": ["Pipfile.lock"], "Gemfile": ["Gemfile.lock"], "composer.json": ["composer.lock"],
             "Cargo.toml": ["Cargo.lock"], "go.mod": ["go.sum"], "pubspec.yaml": ["pubspec.lock"]}
RUNTIME_PINS = [".nvmrc", ".node-version", ".tool-versions", "runtime.txt", ".python-version", ".ruby-version"]
CI_PATHS = [".github/workflows", ".gitlab-ci.yml", ".circleci", "bitbucket-pipelines.yml", "azure-pipelines.yml",
            ".buildkite", "Jenkinsfile", ".drone.yml", ".woodpecker.yml", "cloudbuild.yaml"]
FROZEN = re.compile(r"\bnpm ci\b|pnpm install[^\n]*--frozen-lockfile|yarn install[^\n]*--(?:immutable|frozen-lockfile)|"
                    r"bun install[^\n]*--frozen-lockfile|poetry install|uv sync[^\n]*--(?:frozen|locked)|pip install[^\n]*-r requirements")
PLATFORM_ENV = {"NODE_ENV", "CI", "PORT", "HOST", "HOSTNAME", "PWD", "HOME", "PATH", "TZ", "DEBUG", "MODE", "DEV", "PROD", "SSR",
                "BASE_URL", "VITE_USER_NODE_ENV", "NEXT_RUNTIME", "VERCEL", "NETLIFY", "DENO_DEPLOYMENT_ID"}
SKIP = {".dart_tool", "DerivedData", ".cxx", ".externalNativeBuild", ".symlinks", "ephemeral", "xcuserdata", ".expo-shared", ".fvm", "Carthage", ".kotlin", "Pods", ".gradle", ".expo", "node_modules", ".git", ".vibe-check", "dist", "build", ".next", "vendor", ".venv", "venv"}


def tracked(root: Path):
    try:
        out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, timeout=60)
        if out.returncode == 0:
            return set(out.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        pass
    return None   # not a git repo: "committed" can't be decided


def exists(root, rel):
    return (root / rel).exists()


def manifest_lock(root):
    """[(manifest, [lockfiles present])] for the root manifests."""
    out = []
    for man, locks in MANIFESTS.items():
        if exists(root, man):
            out.append((man, [l for l in locks if exists(root, l)]))
    return out


def ci_files(root):
    found = []
    for p in CI_PATHS:
        q = root / p
        if q.is_dir():
            found += [str(f.relative_to(root)) for f in sorted(q.rglob("*")) if f.is_file() and f.suffix in (".yml", ".yaml", "")]
        elif q.is_file():
            found.append(p)
    return found


def runtime_pin(root):
    for p in RUNTIME_PINS:
        if exists(root, p):
            return p
    try:
        pkg = json.loads((root / "package.json").read_text("utf-8"))
        if isinstance(pkg.get("engines"), dict) and pkg["engines"].get("node"):
            return "package.json engines.node"
        if isinstance(pkg.get("volta"), dict) and pkg["volta"].get("node"):
            return "package.json volta.node"
    except (OSError, ValueError):
        pass
    return None


def readme(root):
    return next((p.name for p in sorted(root.iterdir()) if p.is_file() and p.name.lower().startswith("readme")), None)


def uses_env(root):
    inv = root / ".vibe-check" / "inventory.json"
    try:
        data = json.loads(inv.read_text("utf-8"))
        items = data.get("items", data).get("env_vars", []) if isinstance(data, dict) else []
        names = [i.split()[0] for i in items]
        own = [n for n in names if n not in PLATFORM_ENV and not n.startswith(("VERCEL_", "NETLIFY_", "npm_", "GITHUB_", "RAILWAY_"))]
        return len(own)
    except (OSError, ValueError, AttributeError):
        return None


def env_example(root):
    for p in sorted(root.iterdir()):
        if p.is_file() and re.match(r"^\.env\.(example|sample|template|dist)$|^env\.example$|^example\.env$", p.name):
            return p.name
    return None


def web_root(root):
    return any(exists(root, p) for p in ("index.html", "public/index.html", "src/app", "app", "pages", "src/pages", "src/routes"))


def seo_files(root):
    hits = []
    for base in ("public", "static", "src/app", "app", "."):
        for name in ("robots.txt", "sitemap.xml", "robots.ts", "robots.js", "sitemap.ts", "sitemap.js"):
            if exists(root, f"{base}/{name}"):
                hits.append(f"{base}/{name}".lstrip("./"))
    try:
        pkg = (root / "package.json").read_text("utf-8")
        if "next-sitemap" in pkg or "vite-plugin-sitemap" in pkg or "@astrojs/sitemap" in pkg:
            hits.append("package.json sitemap plugin")
    except OSError:
        pass
    return hits


# ---- the rules: check ID -> function(root, git) returning ("PASS"|"FAIL", evidence) or None (leave it to a helper) ----
def r_lockfile(root, git, cid):
    ml = manifest_lock(root)
    if not ml:
        return None
    for man, locks in ml:
        if not locks:
            return ("FAIL", f"AUTO: {man}:1 has no lockfile next to it (looked for {', '.join(MANIFESTS[man])})")
    if git is None:
        return None
    for man, locks in ml:
        if not any(l in git for l in locks):
            return ("FAIL", f"AUTO: {', '.join(locks)} exists but isn't committed (`git ls-files` doesn't list it)")
    return None   # lockfile committed: the rest of the check (CI uses it, Dependabot) needs a helper


def r_sup001(root, git, cid):
    base = r_lockfile(root, git, cid)
    if base:
        return base
    ml = manifest_lock(root)
    if not ml or git is None:
        return None
    ci = ci_files(root)
    for f in ci:
        try:
            m = FROZEN.search((root / f).read_text("utf-8", "replace"))
        except OSError:
            continue
        if m:
            locks = [l for _, ls in ml for l in ls if l in git]
            return ("PASS", f"AUTO: {', '.join(locks)} committed (`git ls-files`); CI installs from it: {f} uses `{m.group(0)}`")
    return None


def r_ops005(root, git, cid):
    base = r_lockfile(root, git, cid)
    if base:
        return base
    ml = manifest_lock(root)
    if not ml:
        return None
    pin = runtime_pin(root)
    if not pin:
        return ("FAIL", f"AUTO: no runtime version pin (looked for {', '.join(RUNTIME_PINS)} and package.json engines/volta)")
    if git is None:
        return None
    locks = [l for _, ls in ml for l in ls if l in git]
    return ("PASS", f"AUTO: lockfile committed ({', '.join(locks)}, `git ls-files`) and runtime pinned ({pin})")


def r_ci(root, git, cid):
    if ci_files(root):
        return None    # CI exists: whether it lints, types, tests and builds needs a helper
    return ("FAIL", f"AUTO: no CI configuration at all (looked for {', '.join(CI_PATHS)})")


def r_readme(root, git, cid):
    if not readme(root):
        return ("FAIL", "AUTO: no README in the project root")
    return None


def r_mnt007(root, git, cid):
    if not readme(root):
        return ("FAIL", "AUTO: no README in the project root")
    n = uses_env(root)
    if n and not env_example(root):
        return ("FAIL", f"AUTO: the code reads {n} environment variables (inventory.json) but there's no .env.example in the root")
    return None


def r_seo(root, git, cid):
    if not web_root(root):
        return None
    if not seo_files(root):
        return ("FAIL", "AUTO: no robots.txt or sitemap (looked in public/, static/, app/, the root, and for a sitemap plugin)")
    return None


# ---- v3.9: mobile rules (Android, iOS, Firebase). Only answers the files decide for certain. ----
def find_files(root: Path, pred):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP)
        for fn in sorted(filenames):
            rel = (Path(dirpath) / fn).relative_to(root).as_posix()
            if pred(rel):
                out.append(rel)
    return out


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def read(root, rel):
    try:
        return (root / rel).read_text("utf-8", "replace")
    except OSError:
        return ""


def main_manifests(root):
    return [r for r in find_files(root, lambda r: r.endswith("AndroidManifest.xml")) if "/src/debug/" not in r and "/src/androidTest/" not in r]


def r_and001(root, git, cid):
    mans = main_manifests(root)
    if not mans:
        return None
    for rel in mans:
        text = read(root, rel)
        m = re.search(r"<application\b[^>]*>", text, re.S)
        if not m:
            continue
        tag = m.group(0)
        if re.search(r'android:allowBackup="false"', tag):
            return ("PASS", f'AUTO: {rel}:{line_of(text, m.start())} sets android:allowBackup="false"')
        if re.search(r"android:(dataExtractionRules|fullBackupContent)=", tag):
            return None          # backup rules exist: whether they exclude the right files needs a helper
        if re.search(r'android:allowBackup="true"', tag):
            return ("FAIL", f'AUTO: {rel}:{line_of(text, m.start())} sets android:allowBackup="true" with no backup rules excluding private data')
        return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} has no android:allowBackup and no backup rules, so backups are on by default")
    return None


def r_and002(root, git, cid):
    for rel in main_manifests(root):
        text = read(root, rel)
        m = re.search(r'android:debuggable="true"', text)
        if m:
            return ("FAIL", f'AUTO: {rel}:{line_of(text, m.start())} sets android:debuggable="true" in the main manifest')
    for rel in find_files(root, lambda r: re.search(r"(^|/)build\.gradle(\.kts)?$", r) is not None):
        text = read(root, rel)
        m = re.search(r"\brelease\s*\{[^{}]*?\b(?:isDebuggable\s*=\s*true|debuggable\s*(?:=\s*)?true)", text, re.S)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} makes the release build type debuggable")
    return None


def r_and005(root, git, cid):
    for rel in find_files(root, lambda r: "/res/xml/" in r and r.endswith(".xml")):
        text = read(root, rel)
        if "<paths" not in text:
            continue
        m = re.search(r"<root-path\b|<(?:files|external|cache|external-files|external-cache)-path\b[^>]*\bpath=\"(?:\.|/)\"", text)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} shares a whole storage root through the FileProvider")
    return None


def r_and010(root, git, cid):
    for rel in main_manifests(root):
        text = read(root, rel)
        m = re.search(r'android:usesCleartextTraffic="true"', text)
        if m:
            return ("FAIL", f'AUTO: {rel}:{line_of(text, m.start())} allows cleartext traffic for the whole app (android:usesCleartextTraffic="true")')
    for rel in find_files(root, lambda r: "/res/xml/" in r and r.endswith(".xml") and "/src/debug/" not in r):
        text = read(root, rel)
        if "<network-security-config" not in text:
            continue
        body = re.sub(r"<debug-overrides>.*?</debug-overrides>", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        m = re.search(r'<base-config\b[^>]*cleartextTrafficPermitted="true"', body)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(body, m.start())} allows cleartext for every domain (base-config)")
        m = re.search(r'<certificates\b[^>]*src="user"', body)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(body, m.start())} trusts user-installed certificates outside debug-overrides")
    return None


def r_and024(root, git, cid):
    if git is not None:
        keys = sorted(f for f in git if f.endswith((".jks", ".keystore")) and not f.endswith("debug.keystore"))
        if keys:
            return ("FAIL", f"AUTO: signing key file committed: {keys[0]} (`git ls-files`)")
    for rel in find_files(root, lambda r: re.search(r"(^|/)(build\.gradle(\.kts)?|gradle\.properties)$", r) is not None):
        text = read(root, rel)
        m = re.search(r"""(?:storePassword|keyPassword|STORE_PASSWORD|KEY_PASSWORD)\s*[=:]?\s*["']?(?!\$|System\.getenv|project\.|findProperty|keystoreProperties)[^"'\s$]{4,}""", text)
        if m and git is not None and rel in git:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} has a signing password written in a committed file")
    return None


def r_ios001(root, git, cid):
    for rel in find_files(root, lambda r: r.endswith("Info.plist")):
        text = read(root, rel)
        m = re.search(r"<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>", text)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} switches App Transport Security off (NSAllowsArbitraryLoads = true)")
    for rel in find_files(root, lambda r: r.split("/")[-1] in ("app.json", "app.config.json")):
        text = read(root, rel)
        m = re.search(r'"NSAllowsArbitraryLoads"\s*:\s*true', text)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} switches App Transport Security off (NSAllowsArbitraryLoads: true)")
    return None


def r_ios011(root, git, cid):
    for rel in find_files(root, lambda r: r.endswith((".swift", ".m", ".mm", ".h"))):
        text = read(root, rel)
        m = re.search(r"\bUIWebView\b", text)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} uses UIWebView, which App Review rejects")
    return None


def r_mob004(root, git, cid):
    native_ios = find_files(root, lambda r: r.endswith(".pbxproj"))
    if not native_ios:
        return None                      # managed Expo and similar declare the manifest in app config: needs a helper
    found = find_files(root, lambda r: r.endswith("PrivacyInfo.xcprivacy"))
    if not found:
        return ("FAIL", f"AUTO: the iOS project ({native_ios[0]}) has no PrivacyInfo.xcprivacy privacy manifest")
    return None


def r_plt011(root, git, cid):
    for rel in find_files(root, lambda r: r.endswith((".rules",)) and "firestore" in r or r.endswith("storage.rules")):
        text = read(root, rel)
        m = re.search(r"allow\s+[\w, ]*\b(?:read|write)\b[\w, ]*:\s*if\s+(?:true\s*;|request\.time\s*<)", text)
        if m:
            return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start())} is in test mode: `{m.group(0).strip()[:60]}`")
    return None


def r_fbs005(root, git, cid):
    for rel in find_files(root, lambda r: r.endswith("database.rules.json")):
        text = read(root, rel)
        try:
            rules = json.loads(re.sub(r"^\s*//.*$", "", text, flags=re.M)).get("rules", {})
        except ValueError:
            continue
        for key in (".read", ".write"):
            if rules.get(key) is True or rules.get(key) == "true":
                m = re.search(r'"' + re.escape(key) + r'"', text)
                return ("FAIL", f"AUTO: {rel}:{line_of(text, m.start() if m else 0)} sets {key} to true for the whole database")
    return None


RULES = {"SUP-001": r_sup001, "SEC-050": r_lockfile, "OPS-005": r_ops005, "OPS-001": r_ci,
         "MNT-007": r_mnt007, "REL-043": r_readme, "UX-016": r_seo,
         "AND-001": r_and001, "AND-002": r_and002, "AND-005": r_and005, "AND-010": r_and010, "AND-024": r_and024,
         "IOS-001": r_ios001, "IOS-011": r_ios011, "MOB-004": r_mob004, "PLT-011": r_plt011, "FBS-005": r_fbs005}


def settle(root: Path):
    """{check ID: (result, evidence)} for every rule that's certain here."""
    git = tracked(root)
    out = {}
    for cid, fn in RULES.items():
        try:
            got = fn(root, git, cid)
        except Exception:     # a rule never breaks the audit: leave the check to a helper
            got = None
        if got:
            out[cid] = got
    return out


def main(argv):
    root = Path(argv[0] if argv else ".").resolve()
    vc = root / ".vibe-check" / "ledger.d"
    vc.mkdir(parents=True, exist_ok=True)
    done = settle(root)
    rows = ["# Settled by autocheck.py (re-checked by coverage.py; don't edit)", "", "| ID | Result | Evidence |", "|---|---|---|"]
    for cid, (res, ev) in sorted(done.items()):
        rows.append(f"| {cid} | {res + ' 🔬 Confirmed' if res == 'FAIL' else res} | {ev} |")
    (vc / "01-auto.md").write_text("\n".join(rows) + "\n", "utf-8")
    print(f"autocheck: settled {len(done)} of {len(RULES)} checks it knows -> .vibe-check/ledger.d/01-auto.md")
    for cid, (res, ev) in sorted(done.items()):
        print(f"  {cid} {res}: {ev[6:]}")
    left = [c for c in RULES if c not in done]
    if left:
        print(f"  left for the helpers (needs judgement here): {', '.join(left)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
