#!/usr/bin/env python3
"""appscan.py: read a built Android (APK/AAB) or iOS (IPA) app, after the build tools merged everything in.

    python3 appscan.py path/to/app-release.apk [PROJECT_DIR]   -> PROJECT_DIR/.vibe-check/appscan.md

Only reads the file: nothing is installed, run, unpacked to disk or sent anywhere. Ask the user before using it.
- Android: decodes the final (merged) AndroidManifest.xml, including what libraries added, and reports backups,
  debuggable, cleartext, the network security config, every exported component and every permission.
- iOS: reads the app's Info.plist (ATS, permission descriptions, URL schemes), whether the privacy manifest is
  bundled, and whether UIWebView is still linked.
- Both: searches every file in the app (code, bundles, assets) for secrets (masked: first 4 characters only) and for
  test, staging or local server addresses left in the release build.
Python 3.8+, standard library only.
"""
import importlib.util
import plistlib
import re
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANDROID_NS = "http://schemas.android.com/apk/res/android"
# Android attribute resource IDs, for apps whose attribute names were stripped
ATTR_IDS = {0x01010003: "name", 0x01010006: "permission", 0x0101000F: "debuggable", 0x01010010: "exported",
            0x01010280: "allowBackup", 0x010104EC: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
            0x01010270: "targetSdkVersion", 0x0101020C: "minSdkVersion", 0x0101021B: "versionCode", 0x0101021C: "versionName",
            0x01010018: "authorities", 0x0101001B: "grantUriPermissions", 0x01010613: "dataExtractionRules", 0x0101046E: "fullBackupContent"}
TEST_URL = re.compile(rb"https?://(?:localhost|127\.0\.0\.1|10\.0\.2\.2|192\.168\.\d+\.\d+|[\w.-]*(?:staging|stage|dev|test|qa|sandbox|ngrok|loca\.lt|trycloudflare)[\w.-]*)(?::\d+)?[/\w.-]*", re.I)
MAX_ENTRY = 60_000_000


def sweep_secrets():
    spec = importlib.util.spec_from_file_location("vc_sweep", HERE / "sweep.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SECRET_KINDS, mod.mask


# ---- Android binary XML (AXML) ----
def _strings(data, off):
    _, hsize, size, count, _, flags, sstart, _ = struct.unpack_from("<HHIIIIII", data, off)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from("<%dI" % count, data, off + hsize)
    base = off + sstart
    out = []
    for o in offsets:
        p = base + o
        try:
            if utf8:
                n = data[p]; p += 2 if n & 0x80 else 1
                b = data[p]; p += 1
                if b & 0x80:
                    b = ((b & 0x7F) << 8) | data[p]; p += 1
                out.append(data[p:p + b].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", data, p)[0]; p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
                out.append(data[p:p + 2 * n].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out, off + size


def decode_axml(data: bytes) -> str:
    """Turn a binary AndroidManifest.xml into readable XML-like text (one element per line)."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        return data.decode("utf-8", "replace")          # already text
    strings, resmap, lines, depth = [], [], [], 0
    off = struct.unpack_from("<H", data, 2)[0]
    end = len(data)

    def s(i):
        return strings[i] if 0 <= i < len(strings) else ""

    while off + 8 <= end:
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == 0x0001:
            strings, _ = _strings(data, off)
        elif ctype == 0x0180:
            resmap = list(struct.unpack_from("<%dI" % ((csize - hsize) // 4), data, off + hsize))
        elif ctype == 0x0102:
            _, name, astart, asize, acount = struct.unpack_from("<IIHHH", data, off + 16)
            attrs = []
            for k in range(acount):
                a = off + 16 + astart + k * asize
                ans, aname, raw, _, _, dtype, val = struct.unpack_from("<IIIHBBI", data, a)
                nm = s(aname) or ATTR_IDS.get(resmap[aname] if aname < len(resmap) else -1, f"attr{aname}")
                prefix = "android:" if s(ans) == ANDROID_NS or (ans != 0xFFFFFFFF and not s(ans)) else ""
                if raw != 0xFFFFFFFF:
                    v = s(raw)
                elif dtype == 0x12:
                    v = "true" if val else "false"
                elif dtype in (0x10,):
                    v = str(val if val < 0x80000000 else val - 0x100000000)
                elif dtype == 0x01:
                    v = "@0x%08x" % val
                elif dtype == 0x03:
                    v = s(val)
                else:
                    v = "0x%x" % val
                attrs.append(f'{prefix}{nm}="{v}"')
            lines.append("  " * depth + f"<{s(name)} " + " ".join(attrs) + ">")
            depth += 1
        elif ctype == 0x0103:
            depth = max(0, depth - 1)
        off += csize
    return "\n".join(lines)


def android_findings(manifest: str):
    out = []
    app = re.search(r"<application\b[^>]*>", manifest)
    tag = app.group(0) if app else ""
    if 'android:allowBackup="false"' in tag:
        out.append(("ok", "AND-001", "backups off (allowBackup=false)"))
    elif re.search(r"android:(dataExtractionRules|fullBackupContent)=", tag):
        out.append(("check", "AND-001", "backups on, with backup rules: check they exclude tokens and databases"))
    else:
        out.append(("fail", "AND-001", "backups on (allowBackup is true or missing) with no backup rules"))
    if 'android:debuggable="true"' in tag:
        out.append(("fail", "AND-002", "this build is debuggable"))
    if 'android:usesCleartextTraffic="true"' in tag:
        out.append(("fail", "AND-010", "cleartext traffic allowed for the whole app"))
    if "android:networkSecurityConfig=" not in tag and 'android:usesCleartextTraffic="true"' not in tag:
        out.append(("info", "AND-010", "no network security config: platform defaults apply"))
    for m in re.finditer(r"<(activity|activity-alias|service|receiver|provider) ([^>]*)>", manifest):
        attrs = m.group(2)
        name = re.search(r'android:name="([^"]+)"', attrs)
        exported = 'android:exported="true"' in attrs
        perm = re.search(r'android:permission="([^"]+)"', attrs)
        if exported and not perm:
            out.append(("check", "AND-003", f"exported {m.group(1)} without a permission: {name.group(1) if name else '?'}"))
    perms = sorted(set(re.findall(r'<uses-permission[\w-]* [^>]*android:name="([^"]+)"', manifest)))
    restricted = [p for p in perms if re.search(r"QUERY_ALL_PACKAGES|MANAGE_EXTERNAL_STORAGE|READ_SMS|SEND_SMS|RECEIVE_SMS|"
                                                  r"READ_CALL_LOG|WRITE_CALL_LOG|ACCESS_BACKGROUND_LOCATION|BIND_ACCESSIBILITY_SERVICE|"
                                                  r"SCHEDULE_EXACT_ALARM|USE_EXACT_ALARM|REQUEST_INSTALL_PACKAGES", p)]
    for p in restricted:
        out.append(("check", "AND-016", f"restricted permission in the final app: {p}"))
    out.append(("info", "AND-018", f"{len(perms)} permissions in the final app: " + ", ".join(p.split(".")[-1] for p in perms)))
    sdk = re.search(r'android:targetSdkVersion="(\d+)"', manifest)
    if sdk:
        out.append(("info", "MOB-008", f"targetSdkVersion {sdk.group(1)}: compare with Google Play's current requirement (look it up)"))
    return out


def ios_findings(z: zipfile.ZipFile):
    out = []
    names = z.namelist()
    plist_name = next((n for n in names if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)), None)
    if not plist_name:
        return [("info", "IOS", "no Payload/*.app/Info.plist found")]
    app_dir = plist_name.rsplit("/", 1)[0]
    info = plistlib.loads(z.read(plist_name))
    ats = info.get("NSAppTransportSecurity", {}) or {}
    if ats.get("NSAllowsArbitraryLoads"):
        out.append(("fail", "IOS-001", "App Transport Security is off (NSAllowsArbitraryLoads = true)"))
    for k in ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia"):
        if ats.get(k):
            out.append(("check", "IOS-001", f"{k} = true: check a feature needs it"))
    usage = sorted(k for k in info if k.endswith("UsageDescription"))
    out.append(("info", "MOB-002", f"{len(usage)} permission descriptions: " + ", ".join(usage)))
    schemes = [s for t in info.get("CFBundleURLTypes", []) or [] for s in t.get("CFBundleURLSchemes", [])]
    if schemes:
        out.append(("info", "MOB-014", "URL schemes: " + ", ".join(schemes)))
    if not any(n.startswith(app_dir + "/") and n.endswith("PrivacyInfo.xcprivacy") for n in names):
        out.append(("fail", "MOB-004", "no PrivacyInfo.xcprivacy bundled in the app"))
    exe = info.get("CFBundleExecutable")
    if exe and f"{app_dir}/{exe}" in names:
        info_exe = z.getinfo(f"{app_dir}/{exe}")
        if info_exe.file_size <= MAX_ENTRY and b"UIWebView" in z.read(f"{app_dir}/{exe}"):
            out.append(("fail", "IOS-011", "the app binary still references UIWebView (App Review rejects it)"))
    if info.get("ITSAppUsesNonExemptEncryption") is None:
        out.append(("check", "IOS-016", "ITSAppUsesNonExemptEncryption isn't declared"))
    return out


def scan_contents(z: zipfile.ZipFile):
    kinds, mask = sweep_secrets()
    secrets, urls = [], set()
    for info in z.infolist():
        if info.is_dir() or info.file_size > MAX_ENTRY:
            continue
        if re.search(r"\.(png|jpe?g|webp|gif|ttf|otf|woff2?|mp3|mp4|ogg|wav|so)$", info.filename, re.I):
            continue
        try:
            data = z.read(info.filename)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            continue
        text = data.decode("latin-1")
        for _id, _cat, title, rx, _k in kinds:
            for m in rx.finditer(text):
                secrets.append((info.filename, title, mask(m.group(0))))
                break
        for m in TEST_URL.finditer(data):
            urls.add((m.group(0).decode("latin-1")[:120], info.filename))
    return secrets, sorted(urls)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip()); return 0 if argv else 2
    app = Path(argv[0])
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    if not app.is_file() or not zipfile.is_zipfile(app):
        print(f"Not an APK, AAB or IPA: {app}"); return 1
    with zipfile.ZipFile(app) as z:
        names = z.namelist()
        if "AndroidManifest.xml" in names or "base/manifest/AndroidManifest.xml" in names:
            kind = "Android"
            raw = z.read("AndroidManifest.xml" if "AndroidManifest.xml" in names else "base/manifest/AndroidManifest.xml")
            if raw[:2] == b"\x0a\x0b" or (raw[:1] and raw[0] < 0x03 and b"<manifest" not in raw[:200]):
                manifest = ""
                findings = [("info", "AND", "this bundle's manifest is in protobuf form (an .aab); build an APK (bundletool) to read it")]
            else:
                manifest = decode_axml(raw)
                findings = android_findings(manifest)
        elif any(n.startswith("Payload/") for n in names):
            kind, manifest = "iOS", ""
            findings = ios_findings(z)
        else:
            print("This archive has no AndroidManifest.xml or Payload/ folder: not an app build."); return 1
        secrets, urls = scan_contents(z)
    icon = {"fail": "❌", "check": "❓", "ok": "✅", "info": "➖"}
    lines = [f"# App build read: {app.name} ({kind})", "",
             "Read-only: the file was opened as an archive; nothing was installed, run or sent. Secrets are masked.", "",
             "## What the final app declares", "", "| | Check | Finding |", "|---|---|---|"]
    lines += [f"| {icon[s]} | {c} | {t} |" for s, c, t in findings]
    lines += ["", f"## Secrets found in the app ({len(secrets)})", ""]
    lines += [f"- ❌ `{f}`: {t} `{v}`" for f, t, v in secrets] or ["- none matched the secret patterns"]
    lines += ["", f"## Test, staging or local addresses in the app ({len(urls)})", ""]
    lines += [f"- ❓ `{u}` in `{f}`" for u, f in urls[:200]] or ["- none"]
    if manifest:
        lines += ["", "## Final manifest (decoded)", "", "```xml", manifest[:60000], "```"]
    out = root / ".vibe-check" / "appscan.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", "utf-8")
    fails = sum(1 for s, *_ in findings if s == "fail")
    print(f"appscan: {kind} build read -> {out}")
    print(f"  {fails} problem(s) in what it declares · {len(secrets)} possible secret(s) · {len(urls)} test/staging/local address(es)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
