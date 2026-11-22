#!/usr/bin/env python3
"""codemap.py: one map of the code, built once, so helpers open only the lines they need.

    python3 codemap.py [PROJECT_DIR]                 -> .vibe-check/codemap.md and codemap.json
    python3 codemap.py [PROJECT_DIR] --module security   prints just that module's part (for a helper)

For every code file: its size in lines and the names it defines. For every checklist module: the files
and line numbers where that module's topics show up (auth, payments, AI calls, consent...), most hits
first. A helper reads its module's part, then opens only those lines (with some context), instead of
reading whole files or searching the project again. Read-only; nothing is sent anywhere.
Python 3.8+, standard library only.
"""
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".dart_tool", "DerivedData", ".cxx", ".externalNativeBuild", ".symlinks", "ephemeral", "xcuserdata", ".expo-shared", ".fvm", "Carthage", ".kotlin", "Pods", ".gradle", ".expo", "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", ".output", "dist", "build", "out", "coverage",
             ".vibe-check", "vendor", ".venv", "venv", "env", "__pycache__", ".turbo", ".vercel", ".netlify", ".expo",
             "Pods", "target", ".gradle", ".idea", ".cache", "storybook-static", ".wrangler", ".claude", ".agents"}
CODE_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".py", ".rb", ".php", ".go", ".dart",
            ".kt", ".kts", ".java", ".gradle", ".xml", ".plist", ".entitlements", ".xcprivacy", ".pbxproj", ".m", ".mm", ".h", ".pro", ".properties", ".swift", ".html", ".sql", ".prisma", ".rules", ".toml", ".yaml", ".yml", ".json", ".sh", ".tf", ".env.example")
SKIP_FILES = re.compile(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|.*\.min\.js|.*\.map)$")
MAX_BYTES = 600_000

# What each checklist module is about, as search terms (case-insensitive). Broad on purpose: the map points,
# the helper decides.
TOPICS = {
    "security": r"auth|session|jwt|token|cookie|password|login|signup|role|admin|permission|rls|policy|cors|csrf|"
                r"sanitiz|escape|innerhtml|dangerouslysetinnerhtml|eval\(|exec\(|redirect|upload|service_role|secret|rate.?limit",
    "vulnerabilities": r"\"dependencies\"|\"devdependencies\"|requirements|version|cve|audit",
    "supply-chain": r"postinstall|preinstall|<script[^>]+src=|cdn\.|unpkg|jsdelivr|github\.com/[^\s]+/actions|uses:",
    "legal-privacy": r"privacy|consent|cookie|gdpr|dpdp|ccpa|analytics|gtag|posthog|mixpanel|segment|hotjar|clarity|"
                     r"contentsquare|delete.?account|export.?data|pii|personal data|email|phone|address|dob|birth",
    "reliability": r"retry|timeout|backoff|backup|cron|schedule|queue|health|try\s*\{|catch\s*\(|\.catch\(|idempot|transaction|lock",
    "devops": r"workflow|deploy|dockerfile|docker|vercel|netlify|wrangler|fly\.toml|railway|env|secrets\.|branch",
    "launch-ux": r"loading|skeleton|empty|errorboundary|error boundary|404|not.?found|aria-|alt=|<title|meta name|og:|"
                 r"toast|spinner|disabled|placeholder|prefers-reduced-motion|lang=",
    "functional-qa": r"<form|onsubmit|handlesubmit|validate|zod|yup|required|submit|router\.push|navigate\(|useeffect|fetch\(|axios",
    "maintainability": r"test\(|it\(|describe\(|expect\(|eslint|prettier|tsconfig|\"strict\"|todo|fixme|hack",
    "platforms": r"supabase|firebase|lovable|bolt|replit|vercel|netlify|cloudflare|convex|appwrite|clerk|neon",
    "fintech": r"stripe|razorpay|paypal|checkout|payment|invoice|refund|subscription|price|amount|currency|webhook|credits?|wallet|ledger|balance|kyc|pan\b|gstin|ifsc|bank",
    "ai-features": r"openai|anthropic|claude|gpt|gemini|llm|prompt|completion|embedding|moderation|vapi|sarvam|whisper|elevenlabs|ai.?router",
    "ai-agents": r"tool_call|tools:|function_call|mcp|agent|tool_use|toolchoice|tool_choice|allowed_tools",
    "community": r"comment|\bposts?\b|message|\bchat|\breport|\bblock(ed|ing)?\b|\bmute|moderat|follow|profile|review|rating",
    "i18n": r"i18n|locale|translat|intl\.|toLocale|currency|timezone|date-fns|dayjs|moment|rtl|dir=",
    "policies": r"terms|privacy policy|refund policy|cookie policy|acceptable use|/legal|/terms|/privacy",
    "mobile": r"react-native|\bexpo\b|expo-|capacitor|\bionic\b|flutter|swiftui|\bandroid\b|\bios\b|push.?notification|deeplink|deep link",
    "android": r"<manifest|<application|<activity|<service|<receiver|<provider|android:exported|allowbackup|dataextractionrules|debuggable|usescleartexttraffic|network_security_config|"
               r"addjavascriptinterface|setallowfileaccess|onreceivedsslerror|trustmanager|hostnameverifier|fileprovider|"
               r"pendingintent|getparcelableextra|sharedpreferences|keystore|rawquery|execsql|minifyenabled|signingconfig|uses-permission",
    "ios": r"nsapptransportsecurity|nsallowsarbitraryloads|nsexceptiondomains|kseclass|ksecattraccessible|userdefaults|"
           r"fileprotection|isexcludedfrombackup|wkwebview|uiwebview|wkscriptmessagehandler|aswebauthenticationsession|"
           r"lacontext|secaccesscontrol|entitlements|uibackgroundmodes|itsappusesnonexemptencryption|urlsession",
    "mobile-frameworks": r"expo-updates|eas update|codepush|capgo|__dev__|metro|flipper|reactotron|expo-dev-client|"
                         r"nativemodules|methodchannel|platform channel|capacitor|server\.url|allownavigation|"
                         r"react-native-webview|originwhitelist|linking|expo-router|go_router|redux-persist|asyncstorage|mmkv|hive",
    "firebase": r"rules_version|match /|allow (read|write|create|update|delete)|request\.auth|request\.resource|"
                r"onCall|onRequest|https\.oncall|enforceappcheck|appcheck|defineSecret|firebase-admin|getfirestore|"
                r"collection\(|storage\(|messaging|fcm|remoteconfig|crashlytics|analytics",
    "mobile-data": r"sqlite|sqlcipher|room|coredata|swiftdata|realm|hive|isar|mmkv|watermelon|cache|"
                   r"securetextentry|onetimecode|textcontenttype|uipasteboard|clipboard|nslog|os_log|log\.d|console\.log|"
                   r"signout|sign_out|logout|deleteaccount",
    "health": r"health|medical|patient|diagnos|symptom|prescription|hipaa|therapy|clinic",
    "kids-education": r"\bchild(ren)?\b|\bkids?\b|\bminors?\b|student|school|teacher|\bparents?\b|coppa|age.?gate|\bgrades?\b",
    "cloud-infra": r"terraform|aws_|gcp|azure|s3|iam|bucket|kubernetes|helm|vpc|security.?group",
    "desktop-extensions": r"electron|tauri|manifest\.json|chrome\.|browser\.runtime|content_scripts|permissions",
    "enterprise": r"sso|saml|oidc|scim|audit.?log|tenant|organization|workspace|org_id|rbac",
}
DEFS = [re.compile(r"export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)"),
        re.compile(r"export\s+(?:const|let|class)\s+(\w+)"),
        re.compile(r"^\s*(?:async\s+)?def\s+(\w+)", re.M),
        re.compile(r"create\s+(?:or\s+replace\s+)?(?:function|table|view|policy)\s+(?:public\.)?\"?(\w+)", re.I),
        re.compile(r"^\s*(?:app|router)\.(?:get|post|put|patch|delete)\(\s*['\"]([^'\"]+)", re.M)]


def code_files(root: Path):
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]) or not p.is_file():
            continue
        if SKIP_FILES.search(rel) or not rel.lower().endswith(CODE_EXT):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            yield rel, p.read_text("utf-8", "replace")
        except OSError:
            continue


def build(root: Path):
    files, modules = {}, {m: {} for m in TOPICS}
    rx = {m: re.compile(t, re.I) for m, t in TOPICS.items()}
    for rel, text in code_files(root):
        lines = text.splitlines()
        names = []
        for d in DEFS:
            names += [n for n in d.findall(text) if n not in names]
        files[rel] = {"lines": len(lines), "defines": names[:12]}
        for n, line in enumerate(lines, 1):
            if len(line) > 400:
                line = line[:400]
            for m, r in rx.items():
                if r.search(line):
                    modules[m].setdefault(rel, []).append(n)
    return {"files": files, "modules": {m: dict(sorted(v.items(), key=lambda kv: -len(kv[1]))) for m, v in modules.items()}}


def size_plan(n_files: int):
    """How to split the work, by app size: helpers cost a fixed amount each, so small apps don't use them."""
    if n_files <= 50:
        return "small", "no helpers: one session reads the code once and does every module; small re-check sample"
    if n_files <= 200:
        return "medium", "2-3 helpers, each taking several modules"
    return "large", "helpers per area (security; reliability and devops; QA, UX and maintainability; legal; platforms and supply chain; mobile)"


def module_md(name, hits, files):
    out = [f"## {name}", ""]
    if not hits:
        return out + ["No lines match this module's topics. If the profile also rules it out, it's one N/A row.", ""]
    out.append(f"{sum(len(v) for v in hits.values())} matching lines in {len(hits)} files (most first). "
               "Open these lines with a few lines of context; open a whole file only when a check needs it.")
    out.append("")
    for rel, nums in hits.items():
        defs = files.get(rel, {}).get("defines", [])
        out.append(f"- `{rel}` ({files.get(rel, {}).get('lines', '?')} lines{'; defines ' + ', '.join(defs[:6]) if defs else ''}): "
                   + ", ".join(str(n) for n in nums))
    return out + [""]


EXCERPT_CONTEXT = 6      # lines around each match
EXCERPT_MAX_LINES = 700  # per module: past this, the rest is listed as file:line to open if needed
EXCERPT_LINE_CHARS = 200


def windows(nums, total, ctx=EXCERPT_CONTEXT):
    """Merge matches into line ranges with context: [(start, end), ...]."""
    out = []
    for n in sorted(set(nums)):
        a, b = max(1, n - ctx), min(total, n + ctx)
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def excerpts_md(root: Path, name, hits):
    """v5.1: the module's matching lines with context, ready to read, so a helper doesn't open whole files.
    A short file, or one the ranges would mostly cover anyway, is printed whole, once."""
    out = [f"## {name}: excerpts", "",
           f"Each match with {EXCERPT_CONTEXT} lines around it (line numbers on the left). Check from these first. "
           "Open a whole file only when a check needs more than its excerpt, and never open the same file twice.", ""]
    used, rest = 0, []
    for rel, nums in hits.items():
        try:
            lines = (root / rel).read_text("utf-8", "replace").splitlines()
        except OSError:
            continue
        wins = windows(nums, len(lines))
        if len(lines) <= 80 or sum(b - a + 1 for a, b in wins) >= 0.6 * len(lines):
            wins = [(1, len(lines))] if lines else []
        for a, b in wins:
            if used + (b - a + 1) > EXCERPT_MAX_LINES:
                rest.append(f"`{rel}:{a}-{b}`"); continue
            out.append(f"### `{rel}:{a}-{b}`"); out.append("```")
            for k in range(a, b + 1):
                ln = lines[k - 1]
                out.append(f"{k:>5}  {ln[:EXCERPT_LINE_CHARS]}{'…' if len(ln) > EXCERPT_LINE_CHARS else ''}")
            out.append("```"); used += b - a + 1
    if rest:
        out += ["", f"**{len(rest)} more ranges** past the {EXCERPT_MAX_LINES}-line limit (open only those a check needs): " + ", ".join(rest)]
    if not hits:
        out.append("No lines match this module's topics.")
    return out + [""]


def main(argv):
    module = None
    want_excerpts = "--excerpts" in argv
    argv = [a for a in argv if a != "--excerpts"]
    if "--module" in argv:
        i = argv.index("--module"); module = argv[i + 1]; del argv[i:i + 2]
    root = Path(argv[0] if argv else ".").resolve()
    vc = root / ".vibe-check"
    if module:
        data = json.loads((vc / "codemap.json").read_text("utf-8")) if (vc / "codemap.json").exists() else build(root)
        names = [m.strip() for m in module.split(",") if m.strip()]
        bad = [m for m in names if m not in data["modules"]]
        if bad:
            print(f"No module '{bad[0]}'. Modules: {', '.join(data['modules'])}"); return 2
        if want_excerpts:   # several modules: one set of ranges, so a file shared by them is printed once
            merged = {}
            for m in names:
                for rel, nums in data["modules"][m].items():
                    merged.setdefault(rel, []).extend(nums)
            merged = dict(sorted(merged.items(), key=lambda kv: -len(kv[1])))
            print("\n".join(excerpts_md(root, " + ".join(names), merged)))
        else:
            for m in names:
                print("\n".join(module_md(m, data["modules"][m], data["files"])))
        return 0
    data = build(root)
    vc.mkdir(exist_ok=True)
    (vc / "codemap.json").write_text(json.dumps(data, ensure_ascii=False), "utf-8")
    size, plan = size_plan(len(data["files"]))
    md = ["# vibe-check code map", "", f"**App size: {size}** ({len(data['files'])} code files). **Plan:** {plan}.", "",
          f"{len(data['files'])} code files. Helpers: read only your module's part "
          "(`python3 <skill-folder>/scripts/codemap.py --module <name> --excerpts` prints those lines with context); "
          "open a whole file only when a check needs it.", "",
          "## Files", "", "| File | Lines | Defines |", "|---|---|---|"]
    for rel, info in data["files"].items():
        md.append(f"| `{rel}` | {info['lines']} | {', '.join(info['defines'][:8])} |")
    md.append("")
    for m, hits in data["modules"].items():
        md += module_md(m, hits, data["files"])
    (vc / "codemap.md").write_text("\n".join(md), "utf-8")
    busy = sorted(((m, len(h)) for m, h in data["modules"].items()), key=lambda x: -x[1])
    print(f"codemap: {len(data['files'])} code files -> .vibe-check/codemap.md")
    print(f"  app size: {size} -> {plan}")
    print("  files per module: " + " · ".join(f"{m} {n}" for m, n in busy))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
