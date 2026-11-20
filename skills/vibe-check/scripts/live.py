#!/usr/bin/env python3
"""live.py: read the user's signed-in cloud and platform accounts, read-only, after they say yes.

    python3 live.py [PROJECT_DIR] --detect
        Which tools are installed and look signed in. Reads nothing from any account.
    python3 live.py [PROJECT_DIR] --run PROVIDER --consent [--profile NAME] [--project ID]
        Read that account. Only after the user said yes, and with LIVE: <provider>: yes in .vibe-check/answers.md.

Providers: github, firebase, supabase, vercel, netlify, aws, gcp, azure, prowler-aws, prowler-gcp, prowler-azure.

Rules this script enforces itself:
- Only commands on a read-only allow-list run (list, describe, get, show, view). Anything else is refused.
- It uses the login you already have. It never asks for, stores or prints keys or tokens.
- It reads settings, never your data: no listing files in buckets, no reading user rows, no exports.
- Supabase is read through a read-only connection you set yourself in VIBE_CHECK_DB_URL, with every query a SELECT,
  inside a read-only transaction.
- Results stay in .vibe-check/live/ (git-ignored). Account IDs are shortened to their last 4 characters.
Python 3.8+, standard library only (it calls the tools you already have installed).
"""
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TIMEOUT = 60
RISKY_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200, 11211, 1433, 5984}
WRITE_WORDS = re.compile(r"(?:^|[\s:/-])(?:delete|remove|rm|create|put|update|set|write|deploy|enable|disable|attach|detach|modify|start|stop|"
                         r"terminate|invoke|restore|apply|push|send|add|revoke|grant|import|export|login|logout|purge|rotate|reset|run-instances|"
                         r"generate|upload|download|cp|mv|sync|rb|mb)(?:$|[\s:/-])", re.I)


class Refused(Exception):
    pass


def mask(s):
    s = str(s or "")
    return ("…" + s[-4:]) if len(s) > 4 else s


def is_read_only(argv):
    """The allow-list. True only for commands that read settings."""
    tool = Path(argv[0]).name
    rest = argv[1:]
    words = [a for a in rest if not a.startswith("-")]
    if tool == "aws":
        if words[:2] == ["configure", "get"]:
            return True
        return len(words) >= 2 and re.match(r"^(get|list|describe)-", words[1]) is not None and words[1] not in ("get-secret-value", "get-object", "get-parameter", "get-parameters")
    deny = ("create", "delete", "update", "set-", "add-", "remove", "deploy", "enable", "disable", "patch", "import", "export",
            "reset", "start", "stop", "restart", "purge", "assign", "unassign", "regenerate", "rotate", "invoke", "ssh")
    if tool == "gcloud":
        allowed = {"list", "describe", "get-iam-policy", "get-value"}
        return any(w in allowed for w in words) and not any(w.startswith(deny) for w in words)
    if tool == "az":
        return any(w in ("list", "show") for w in words) and not any(w.startswith(deny) for w in words)
    if tool == "gh":
        if words[:2] in (["repo", "view"], ["auth", "status"]):
            return True
        if words[:1] == ["api"]:
            return not any(a in ("-X", "--method", "-f", "-F", "--field", "--raw-field", "--input") for a in rest)
        return False
    if tool == "firebase":
        return bool(words) and words[0] in ("projects:list", "apps:list")
    if tool == "vercel":
        return words[:1] == ["whoami"] or words[:2] in (["env", "ls"], ["project", "ls"], ["projects", "ls"])
    if tool == "netlify":
        return bool(words) and words[0] in ("status", "env:list")
    if tool == "prowler":
        return True                      # a read-only scanner
    if tool == "psql":
        q = rest[rest.index("-c") + 1] if "-c" in rest else ""
        return q.lstrip().lower().startswith("select ") and ";" not in q.rstrip().rstrip(";")
    return False


def run(argv, env=None, cwd=None, timeout=TIMEOUT):
    # second net for tools whose allow-list is by sub-command name (aws operations are checked by their get/list/describe prefix)
    if not is_read_only(argv) or (Path(argv[0]).name in ("az", "vercel", "netlify", "firebase") and WRITE_WORDS.search(" ".join(argv[1:3]))):
        raise Refused("refused (not on the read-only allow-list): " + " ".join(argv[:4]))
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{argv[0]} isn't installed"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"


def jrun(argv, **kw):
    rc, out, err = run(argv, **kw)
    if rc != 0:
        return None, err.strip()[:200]
    try:
        return json.loads(out or "null"), ""
    except ValueError:
        return None, "not JSON"


class Recorder:
    def __init__(self, provider):
        self.provider, self.results, self.account = provider, [], ""

    def add(self, slug, checks, status, summary, cmd):
        """status: pass | fail | check | info."""
        rid = f"{self.provider}:{slug}"
        self.results.append({"id": rid, "checks": checks, "status": status, "summary": summary[:300], "cmd": cmd})


# ---- providers ----
def p_github(rec, root, opts):
    repo, err = jrun(["gh", "repo", "view", "--json", "nameWithOwner,defaultBranchRef,visibility,owner"], cwd=root)
    if not repo:
        rec.add("repo", [], "info", f"no GitHub repo for this folder or not signed in ({err})", "gh repo view"); return
    full, branch = repo["nameWithOwner"], (repo.get("defaultBranchRef") or {}).get("name") or "main"
    rec.account = full
    info, _ = jrun(["gh", "api", f"repos/{full}"])
    sa = (info or {}).get("security_and_analysis") or {}
    ss = (sa.get("secret_scanning") or {}).get("status"); pp = (sa.get("secret_scanning_push_protection") or {}).get("status")
    if ss is None:
        rec.add("secret-scanning", ["OPS-004", "SUP-019", "SEC-026"], "check", "secret scanning status can't be read with this login (needs admin)", f"gh api repos/{full}")
    else:
        ok = ss == "enabled" and pp == "enabled"
        rec.add("secret-scanning", ["OPS-004", "SUP-019", "SEC-026"], "pass" if ok else "fail",
                f"secret scanning {ss}, push protection {pp or 'unknown'}", f"gh api repos/{full}")
    rc, out, e = run(["gh", "api", f"repos/{full}/branches/{branch}/protection"])
    rules, _ = jrun(["gh", "api", f"repos/{full}/rulesets"])
    if rc == 0:
        prot = json.loads(out or "{}")
        reviews = prot.get("required_pull_request_reviews")
        rec.add("branch-protection", ["SUP-020"], "pass" if reviews else "fail",
                f"{branch} is protected" + (", reviews required" if reviews else ", but no reviews are required"), f"gh api repos/{full}/branches/{branch}/protection")
    elif rules:
        rec.add("branch-protection", ["SUP-020"], "check", f"{len(rules)} ruleset(s) exist; check they cover {branch} with required reviews", f"gh api repos/{full}/rulesets")
    elif "not protected" in (e or "").lower():
        rec.add("branch-protection", ["SUP-020"], "fail", f"{branch} has no branch protection and no rulesets", f"gh api repos/{full}/branches/{branch}/protection")
    else:
        rec.add("branch-protection", ["SUP-020"], "check", "branch protection can't be read with this login", f"gh api repos/{full}/branches/{branch}/protection")
    perms, _ = jrun(["gh", "api", f"repos/{full}/actions/permissions/workflow"])
    if perms:
        dflt = perms.get("default_workflow_permissions")
        rec.add("workflow-permissions", ["SUP-009"], "pass" if dflt == "read" else "fail",
                f"default GITHUB_TOKEN permission is {dflt}", f"gh api repos/{full}/actions/permissions/workflow")
    rc, _, _ = run(["gh", "api", f"repos/{full}/vulnerability-alerts"])
    rec.add("dependabot-alerts", ["OPS-003"], "pass" if rc == 0 else "fail",
            "Dependabot security alerts are on" if rc == 0 else "Dependabot security alerts are off", f"gh api repos/{full}/vulnerability-alerts")
    alerts, _ = jrun(["gh", "api", f"repos/{full}/dependabot/alerts?state=open&per_page=100"])
    if isinstance(alerts, list):
        bad = [a for a in alerts if ((a.get("security_advisory") or {}).get("severity") or "").lower() in ("critical", "high")]
        rec.add("open-alerts", ["VUL-005"], "fail" if bad else "info",
                f"{len(bad)} open critical/high Dependabot alert(s)" if bad else f"{len(alerts)} open Dependabot alert(s), none critical or high",
                f"gh api repos/{full}/dependabot/alerts?state=open")
    owner = repo.get("owner") or {}
    if owner.get("login") and (info or {}).get("owner", {}).get("type") == "Organization":
        org, _ = jrun(["gh", "api", f"orgs/{owner['login']}"])
        tfa = (org or {}).get("two_factor_requirement_enabled")
        if tfa is not None:
            rec.add("org-2fa", ["SUP-021"], "pass" if tfa else "fail", f"organisation 2FA requirement {'on' if tfa else 'off'}", f"gh api orgs/{owner['login']}")


def aws_args(opts):
    return (["--profile", opts["profile"]] if opts.get("profile") else []) + ["--output", "json"]


def p_aws(rec, root, opts):
    a = aws_args(opts)
    who, err = jrun(["aws", "sts", "get-caller-identity"] + a)
    if not who:
        rec.add("identity", [], "info", f"not signed in to AWS ({err})", "aws sts get-caller-identity"); return
    acct = who["Account"]; rec.account = mask(acct)
    pab, err = jrun(["aws", "s3control", "get-public-access-block", "--account-id", acct] + a)
    cfg = (pab or {}).get("PublicAccessBlockConfiguration") or {}
    ok = bool(cfg) and all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    rec.add("s3-account-public-access-block", ["CLD-028"], "pass" if ok else "fail",
            "account-wide S3 Block Public Access is fully on" if ok else "account-wide S3 Block Public Access isn't fully on", "aws s3control get-public-access-block")
    buckets, _ = jrun(["aws", "s3api", "list-buckets"] + a)
    names = [b["Name"] for b in (buckets or {}).get("Buckets", [])][:50]
    public = []
    for n in names:
        st, _ = jrun(["aws", "s3api", "get-bucket-policy-status", "--bucket", n] + a)
        if ((st or {}).get("PolicyStatus") or {}).get("IsPublic"):
            public.append(n)
    if names:
        rec.add("s3-public-buckets", ["CLD-001", "CLD-030"], "fail" if public else "pass",
                f"public by bucket policy: {', '.join(public)}" if public else f"none of {len(names)} buckets is public by policy", "aws s3api get-bucket-policy-status")
    summ, _ = jrun(["aws", "iam", "get-account-summary"] + a)
    sm = (summ or {}).get("SummaryMap") or {}
    if sm:
        bad = [] + (["root has no MFA"] if not sm.get("AccountMFAEnabled") else []) + (["root has access keys"] if sm.get("AccountAccessKeysPresent") else [])
        rec.add("root-account", ["CLD-007"], "fail" if bad else "pass", "; ".join(bad) or "root has MFA and no access keys", "aws iam get-account-summary")
    users, _ = jrun(["aws", "iam", "list-users"] + a)
    no_mfa, old_keys, console = [], [], 0
    now = datetime.now(timezone.utc)
    for u in (users or {}).get("Users", [])[:100]:
        name = u["UserName"]
        rc, _, _ = run(["aws", "iam", "get-login-profile", "--user-name", name] + a)
        if rc == 0:
            console += 1
            mfa, _ = jrun(["aws", "iam", "list-mfa-devices", "--user-name", name] + a)
            if not (mfa or {}).get("MFADevices"):
                no_mfa.append(name)
        keys, _ = jrun(["aws", "iam", "list-access-keys", "--user-name", name] + a)
        for k in (keys or {}).get("AccessKeyMetadata", []):
            try:
                age = (now - datetime.fromisoformat(k["CreateDate"].replace("Z", "+00:00"))).days
            except (KeyError, ValueError):
                continue
            if k.get("Status") == "Active" and age > 90:
                old_keys.append(f"{name} ({age} days)")
    if users is not None:
        rec.add("iam-user-mfa", ["CLD-023"], "fail" if no_mfa else "pass",
                f"console users without MFA: {', '.join(no_mfa)}" if no_mfa else f"all {console} console user(s) have MFA", "aws iam list-mfa-devices")
        rec.add("iam-old-keys", ["CLD-024"], "fail" if old_keys else "pass",
                f"active access keys older than 90 days: {', '.join(old_keys[:10])}" if old_keys else "no active access key is older than 90 days", "aws iam list-access-keys")
    pol, err = jrun(["aws", "iam", "get-account-password-policy"] + a)
    if pol:
        ln = pol.get("PasswordPolicy", {}).get("MinimumPasswordLength", 0)
        rec.add("password-policy", ["CLD-025"], "pass" if ln >= 12 else "fail", f"minimum password length {ln}", "aws iam get-account-password-policy")
    elif console:
        rec.add("password-policy", ["CLD-025"], "fail", "no account password policy, and there are console users", "aws iam get-account-password-policy")
    trails, _ = jrun(["aws", "cloudtrail", "describe-trails"] + a)
    tl = (trails or {}).get("trailList", [])
    if trails is not None:
        multi = [t for t in tl if t.get("IsMultiRegionTrail")]
        rec.add("cloudtrail", ["CLD-009"], "pass" if multi else "fail",
                f"multi-region trail: {multi[0]['Name']}" if multi else "no multi-region CloudTrail trail", "aws cloudtrail describe-trails")
        if multi:
            val = all(t.get("LogFileValidationEnabled") for t in multi)
            rec.add("cloudtrail-validation", ["CLD-033"], "pass" if val else "fail",
                    "log file validation on" if val else "log file validation off on a trail", "aws cloudtrail describe-trails")
    gd, _ = jrun(["aws", "guardduty", "list-detectors"] + a)
    if gd is not None:
        rec.add("guardduty", ["CLD-026"], "pass" if gd.get("DetectorIds") else "fail",
                "GuardDuty is on in the default region" if gd.get("DetectorIds") else "GuardDuty is off in the default region", "aws guardduty list-detectors")
    sgs, _ = jrun(["aws", "ec2", "describe-security-groups"] + a)
    open_ports = []
    for g in (sgs or {}).get("SecurityGroups", []):
        for perm in g.get("IpPermissions", []):
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not world:
                continue
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            if perm.get("IpProtocol") == "-1":
                lo, hi = 0, 65535
            hits = sorted(p for p in RISKY_PORTS if lo <= p <= hi)
            if hits:
                open_ports.append(f"{g.get('GroupId')} ports {','.join(map(str, hits))}")
    if sgs is not None:
        rec.add("open-ports", ["CLD-010", "CLD-012"], "fail" if open_ports else "pass",
                f"open to the internet: {'; '.join(open_ports[:8])}" if open_ports else "no security group opens SSH, RDP or database ports to the internet", "aws ec2 describe-security-groups")
    dbs, _ = jrun(["aws", "rds", "describe-db-instances"] + a)
    if dbs is not None and dbs.get("DBInstances"):
        inst = dbs["DBInstances"]
        pub = [d["DBInstanceIdentifier"] for d in inst if d.get("PubliclyAccessible")]
        unenc = [d["DBInstanceIdentifier"] for d in inst if not d.get("StorageEncrypted")]
        fragile = [d["DBInstanceIdentifier"] for d in inst if not d.get("DeletionProtection") or not d.get("BackupRetentionPeriod")]
        rec.add("rds-public", ["CLD-010"], "fail" if pub else "pass", f"publicly accessible databases: {', '.join(pub)}" if pub else "no RDS database is publicly accessible", "aws rds describe-db-instances")
        rec.add("rds-encryption", ["CLD-002"], "fail" if unenc else "pass", f"unencrypted databases: {', '.join(unenc)}" if unenc else "all RDS databases are encrypted", "aws rds describe-db-instances")
        rec.add("rds-protection", ["CLD-037"], "fail" if fragile else "pass", f"no deletion protection or backups: {', '.join(fragile)}" if fragile else "all RDS databases have backups and deletion protection", "aws rds describe-db-instances")
    snaps, _ = jrun(["aws", "ec2", "describe-snapshots", "--owner-ids", "self", "--restorable-by-user-ids", "all"] + a)
    if snaps is not None:
        s = [x["SnapshotId"] for x in snaps.get("Snapshots", [])]
        rec.add("public-snapshots", ["CLD-032"], "fail" if s else "pass", f"public EBS snapshots: {', '.join(s[:5])}" if s else "no public EBS snapshots", "aws ec2 describe-snapshots --restorable-by-user-ids all")
    keys, _ = jrun(["aws", "kms", "list-keys"] + a)
    norot = []
    for k in (keys or {}).get("Keys", [])[:30]:
        meta, _ = jrun(["aws", "kms", "describe-key", "--key-id", k["KeyId"]] + a)
        km = (meta or {}).get("KeyMetadata") or {}
        if km.get("KeyManager") == "CUSTOMER" and km.get("KeyState") == "Enabled" and km.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT":
            st, _ = jrun(["aws", "kms", "get-key-rotation-status", "--key-id", k["KeyId"]] + a)
            if not (st or {}).get("KeyRotationEnabled"):
                norot.append(mask(k["KeyId"]))
    if keys is not None:
        rec.add("kms-rotation", ["CLD-027"], "fail" if norot else "pass", f"customer keys without rotation: {', '.join(norot)}" if norot else "customer-managed keys rotate (or there are none)", "aws kms get-key-rotation-status")
    bud, _ = jrun(["aws", "budgets", "describe-budgets", "--account-id", acct] + a)
    if bud is not None:
        rec.add("budgets", ["CLD-022"], "pass" if bud.get("Budgets") else "fail", f"{len(bud.get('Budgets', []))} budget(s)" if bud.get("Budgets") else "no AWS budgets", "aws budgets describe-budgets")
    fns, _ = jrun(["aws", "lambda", "list-functions"] + a)
    open_fn = []
    for f in (fns or {}).get("Functions", [])[:50]:
        url, _ = jrun(["aws", "lambda", "get-function-url-config", "--function-name", f["FunctionName"]] + a)
        if url and url.get("AuthType") == "NONE":
            open_fn.append(f["FunctionName"])
    if fns is not None:
        rec.add("lambda-urls", ["CLD-039"], "check" if open_fn else "pass",
                f"function URLs open to anyone (check they verify callers): {', '.join(open_fn)}" if open_fn else "no Lambda function URL is open without auth", "aws lambda get-function-url-config")


def gproj(opts, root):
    if opts.get("project"):
        return opts["project"]
    rc = root / ".firebaserc"
    if rc.exists():
        try:
            return json.loads(rc.read_text("utf-8")).get("projects", {}).get("default")
        except ValueError:
            pass
    rcode, out, _ = run(["gcloud", "config", "get-value", "project"])
    return out.strip() if rcode == 0 and out.strip() else None


def p_gcp(rec, root, opts):
    proj = gproj(opts, root)
    if not proj:
        rec.add("project", [], "info", "no Google Cloud project set (gcloud config or --project)", "gcloud config get-value project"); return
    rec.account = proj
    f = ["--project", proj, "--format=json"]
    pol, err = jrun(["gcloud", "projects", "get-iam-policy", proj, "--format=json"])
    if pol:
        owners = [m for b in pol.get("bindings", []) if b.get("role") == "roles/owner" for m in b.get("members", [])]
        public = [f"{b['role']}" for b in pol.get("bindings", []) if set(b.get("members", [])) & {"allUsers", "allAuthenticatedUsers"}]
        rec.add("owners", ["CLD-029"], "fail" if len(owners) > 3 else "pass", f"{len(owners)} project owner(s)", "gcloud projects get-iam-policy")
        rec.add("public-iam", ["CLD-030"], "fail" if public else "pass", f"public grants: {', '.join(public)}" if public else "no project-level grant to allUsers or allAuthenticatedUsers", "gcloud projects get-iam-policy")
    sas, _ = jrun(["gcloud", "iam", "service-accounts", "list"] + f)
    with_keys = []
    for sa in (sas or [])[:50]:
        keys, _ = jrun(["gcloud", "iam", "service-accounts", "keys", "list", "--iam-account", sa["email"], "--managed-by=user"] + f)
        if keys:
            with_keys.append(sa["email"].split("@")[0])
    if sas is not None:
        rec.add("sa-keys", ["CLD-031"], "fail" if with_keys else "pass",
                f"service accounts with downloaded keys: {', '.join(with_keys)}" if with_keys else "no service account has user-managed keys", "gcloud iam service-accounts keys list --managed-by=user")
    buckets, _ = jrun(["gcloud", "storage", "buckets", "list"] + f)
    public_b, no_pap = [], []
    for b in (buckets or [])[:50]:
        name = b.get("name") or b.get("id")
        if (b.get("public_access_prevention") or (b.get("iamConfiguration") or {}).get("publicAccessPrevention")) != "enforced":
            no_pap.append(name)
        bp, _ = jrun(["gcloud", "storage", "buckets", "get-iam-policy", f"gs://{name}", "--format=json"])
        if any(set(x.get("members", [])) & {"allUsers", "allAuthenticatedUsers"} for x in (bp or {}).get("bindings", [])):
            public_b.append(name)
    if buckets is not None:
        rec.add("public-buckets", ["CLD-001"], "fail" if public_b else "pass", f"public buckets: {', '.join(public_b)}" if public_b else f"none of {len(buckets)} buckets is public", "gcloud storage buckets get-iam-policy")
        rec.add("public-access-prevention", ["CLD-028"], "fail" if no_pap else "pass",
                f"public access prevention not enforced on: {', '.join(no_pap[:8])}" if no_pap else "public access prevention enforced on every bucket", "gcloud storage buckets list")
    fw, _ = jrun(["gcloud", "compute", "firewall-rules", "list"] + f)
    open_r = []
    for r in fw or []:
        if r.get("direction") != "INGRESS" or r.get("disabled") or "0.0.0.0/0" not in r.get("sourceRanges", []):
            continue
        for al in r.get("allowed", []):
            ports = al.get("ports") or (["0-65535"] if al.get("IPProtocol") in ("all", "tcp") else [])
            for pr in ports:
                lo, _, hi = pr.partition("-")
                lo, hi = int(lo), int(hi or lo)
                hits = sorted(p for p in RISKY_PORTS if lo <= p <= hi)
                if hits:
                    open_r.append(f"{r['name']} ports {','.join(map(str, hits))}")
    if fw is not None:
        rec.add("open-ports", ["CLD-010", "CLD-012"], "fail" if open_r else "pass",
                f"open to the internet: {'; '.join(open_r[:8])}" if open_r else "no firewall rule opens SSH, RDP or database ports to the internet", "gcloud compute firewall-rules list")
    sql, _ = jrun(["gcloud", "sql", "instances", "list"] + f)
    if sql:
        world = [i["name"] for i in sql if any(n.get("value") == "0.0.0.0/0" for n in ((i.get("settings") or {}).get("ipConfiguration") or {}).get("authorizedNetworks", []))]
        nobk = [i["name"] for i in sql if not (((i.get("settings") or {}).get("backupConfiguration") or {}).get("enabled"))]
        rec.add("sql-public", ["CLD-010"], "fail" if world else "pass", f"Cloud SQL open to 0.0.0.0/0: {', '.join(world)}" if world else "no Cloud SQL instance allows 0.0.0.0/0", "gcloud sql instances list")
        rec.add("sql-backups", ["CLD-037"], "fail" if nobk else "pass", f"no automated backups: {', '.join(nobk)}" if nobk else "all Cloud SQL instances have automated backups", "gcloud sql instances list")
    keys, _ = jrun(["gcloud", "services", "api-keys", "list"] + f)
    if keys is not None:
        loose = [k.get("displayName") or mask(k.get("uid")) for k in keys if not k.get("restrictions")]
        rec.add("api-key-restrictions", ["FBS-013"], "fail" if loose else "pass",
                f"API keys with no restrictions: {', '.join(loose)}" if loose else f"all {len(keys)} API key(s) are restricted", "gcloud services api-keys list")


def p_firebase(rec, root, opts):
    projs, err = jrun(["firebase", "projects:list", "--json"])
    lst = (projs or {}).get("result", []) if isinstance(projs, dict) else []
    if projs is None:
        rec.add("projects", [], "info", f"not signed in to the Firebase CLI ({err})", "firebase projects:list"); return
    ids = [p.get("projectId") for p in lst]
    rec.account = gproj(opts, root) or (ids[0] if ids else "")
    separate = any(re.search(r"dev|staging|test|qa", i or "", re.I) for i in ids) and any(not re.search(r"dev|staging|test|qa", i or "", re.I) for i in ids)
    rec.add("projects", ["FBS-012"], "pass" if separate else "check",
            f"{len(ids)} Firebase project(s), with a separate development or staging project" if separate else f"{len(ids)} Firebase project(s); no separate development or staging project is obvious",
            "firebase projects:list")
    if shutil.which("gcloud") and rec.account:
        keys, _ = jrun(["gcloud", "services", "api-keys", "list", "--project", rec.account, "--format=json"])
        if keys is not None:
            loose = [k.get("displayName") or mask(k.get("uid")) for k in keys if not k.get("restrictions")]
            rec.add("api-key-restrictions", ["FBS-013"], "fail" if loose else "pass",
                    f"API keys with no restrictions: {', '.join(loose)}" if loose else f"all {len(keys)} API key(s) are restricted", "gcloud services api-keys list")


def p_azure(rec, root, opts):
    acct, err = jrun(["az", "account", "show", "-o", "json"])
    if not acct:
        rec.add("account", [], "info", f"not signed in to Azure ({err})", "az account show"); return
    rec.account = mask(acct.get("id"))
    st, _ = jrun(["az", "storage", "account", "list", "-o", "json"])
    if st is not None:
        pub = [s["name"] for s in st if s.get("allowBlobPublicAccess")]
        tls = [s["name"] for s in st if s.get("minimumTlsVersion") not in ("TLS1_2", "TLS1_3")]
        http = [s["name"] for s in st if s.get("enableHttpsTrafficOnly") is False]
        rec.add("storage-public", ["CLD-028", "CLD-001"], "fail" if pub else "pass", f"blob public access allowed on: {', '.join(pub)}" if pub else "no storage account allows blob public access", "az storage account list")
        rec.add("storage-tls", ["CLD-034"], "fail" if tls else "pass", f"minimum TLS below 1.2 on: {', '.join(tls)}" if tls else "storage accounts require TLS 1.2+", "az storage account list")
        if http:
            rec.add("storage-https", ["CLD-011"], "fail", f"HTTP allowed on: {', '.join(http)}", "az storage account list")
    nsgs, _ = jrun(["az", "network", "nsg", "list", "-o", "json"])
    open_r = []
    for n in nsgs or []:
        for r in n.get("securityRules", []):
            if r.get("direction") != "Inbound" or r.get("access") != "Allow" or r.get("sourceAddressPrefix") not in ("*", "Internet", "0.0.0.0/0", "Any"):
                continue
            rng = r.get("destinationPortRange") or ""
            ranges = [rng] if rng else r.get("destinationPortRanges", [])
            for pr in ranges:
                if pr == "*":
                    lo, hi = 0, 65535
                else:
                    a_, _, b_ = pr.partition("-"); lo, hi = int(a_), int(b_ or a_)
                hits = sorted(p for p in RISKY_PORTS if lo <= p <= hi)
                if hits:
                    open_r.append(f"{n['name']}/{r['name']} ports {','.join(map(str, hits))}")
    if nsgs is not None:
        rec.add("open-ports", ["CLD-010", "CLD-012"], "fail" if open_r else "pass",
                f"open to the internet: {'; '.join(open_r[:8])}" if open_r else "no NSG rule opens SSH, RDP or database ports to the internet", "az network nsg list")
    pr, _ = jrun(["az", "security", "pricing", "list", "-o", "json"])
    if pr is not None:
        items = pr.get("value", pr) if isinstance(pr, dict) else pr
        on = [p.get("name") for p in items if p.get("pricingTier") == "Standard"]
        rec.add("defender", ["CLD-026"], "pass" if on else "fail", f"Defender for Cloud on for: {', '.join(on[:6])}" if on else "Defender for Cloud plans are all off (Free tier)", "az security pricing list")
    kv, _ = jrun(["az", "keyvault", "list", "-o", "json"])
    if kv:
        weak = [k["name"] for k in kv if not (k.get("properties") or {}).get("enablePurgeProtection")]
        rec.add("keyvault-purge", ["CLD-035"], "fail" if weak else "pass", f"no purge protection: {', '.join(weak)}" if weak else "every Key Vault has purge protection", "az keyvault list")
    apps, _ = jrun(["az", "webapp", "list", "-o", "json"])
    if apps:
        http = [w["name"] for w in apps if not w.get("httpsOnly")]
        if http:
            rec.add("webapp-https", ["CLD-011"], "fail", f"web apps that allow HTTP: {', '.join(http)}", "az webapp list")


SUPA_Q = {
    "no-rls": "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind in ('r','p') and not c.relrowsecurity order by 1",
    "true-policies": "select tablename || '.' || policyname from pg_policies where schemaname = 'public' and (qual = 'true' or with_check = 'true') order by 1",
    "views-bypass": "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'v' and not coalesce(array_to_string(c.reloptions, ',') like '%security_invoker=true%', false) order by 1",
    "public-buckets": "select name from storage.buckets where public order by 1",
}


def p_supabase(rec, root, opts):
    url = os.environ.get("VIBE_CHECK_DB_URL")
    if not url:
        rec.add("connection", [], "info", "no read-only connection: set VIBE_CHECK_DB_URL yourself (a read-only role) to let vibe-check read the live database", "env VIBE_CHECK_DB_URL")
        return
    env = dict(os.environ, PGOPTIONS="-c default_transaction_read_only=on")
    rows = {}
    for key, q in SUPA_Q.items():
        rc, out, err = run(["psql", url, "-At", "-c", q], env=env)
        rows[key] = [l for l in out.splitlines() if l.strip()] if rc == 0 else None
    m = re.search(r"@(?:db\.)?([\w-]+)", url)
    rec.account = ("db " + mask(m.group(1))) if m else "database"
    if rows["no-rls"] is not None:
        rec.add("rls", ["PLT-001"], "fail" if rows["no-rls"] else "pass",
                f"tables without RLS: {', '.join(rows['no-rls'][:12])}" if rows["no-rls"] else "RLS is on for every public table", "psql: pg_class.relrowsecurity")
        migrated = set()
        for f in sorted((root / "supabase" / "migrations").glob("*.sql")) if (root / "supabase" / "migrations").exists() else []:
            migrated |= set(re.findall(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?public\"?\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security", f.read_text("utf-8", "replace"), re.I))
        drift = sorted(migrated & set(rows["no-rls"]))
        if migrated:
            rec.add("drift-rls", ["PLT-052"], "fail" if drift else "pass",
                    f"migrations turn RLS on, but it's off live for: {', '.join(drift)}" if drift else f"live RLS matches the migrations for {len(migrated)} table(s)", "psql vs supabase/migrations")
    if rows["true-policies"] is not None:
        rec.add("true-policies", ["PLT-002"], "fail" if rows["true-policies"] else "pass",
                f"policies that allow everything: {', '.join(rows['true-policies'][:10])}" if rows["true-policies"] else "no live policy uses true", "psql: pg_policies")
    if rows["views-bypass"] is not None:
        rec.add("views", ["PLT-006"], "fail" if rows["views-bypass"] else "pass",
                f"views without security_invoker: {', '.join(rows['views-bypass'][:10])}" if rows["views-bypass"] else "every public view uses security_invoker", "psql: pg_class.reloptions")
    if rows["public-buckets"] is not None:
        rec.add("public-buckets", ["PLT-004"], "check" if rows["public-buckets"] else "pass",
                f"public buckets (check none holds private files): {', '.join(rows['public-buckets'])}" if rows["public-buckets"] else "no public storage bucket", "psql: storage.buckets")


SECRET_NAME = re.compile(r"^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)\w*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|_SK_|API_KEY_SECRET)")


def p_env_names(rec, names, cmd):
    leaky = sorted({n for n in names if SECRET_NAME.search(n)})
    rec.add("public-env-secrets", ["SEC-022"], "fail" if leaky else "pass",
            f"browser-visible variables named like secrets: {', '.join(leaky)}" if leaky else f"no browser-visible variable is named like a secret ({len(set(names))} checked)", cmd)


def p_vercel(rec, root, opts):
    rc, out, err = run(["vercel", "whoami"], cwd=root)
    if rc != 0:
        rec.add("account", [], "info", f"not signed in to Vercel ({err.strip()[:120]})", "vercel whoami"); return
    rec.account = out.strip().splitlines()[-1] if out.strip() else "vercel"
    rc, out, _ = run(["vercel", "env", "ls"], cwd=root)
    names = re.findall(r"^\s*([A-Z][A-Z0-9_]{2,})\s", out, re.M) if rc == 0 else []
    if rc == 0:
        p_env_names(rec, names, "vercel env ls")


def p_netlify(rec, root, opts):
    rc, out, err = run(["netlify", "status", "--json"], cwd=root)
    if rc != 0:
        rec.add("account", [], "info", f"not signed in to Netlify or no linked site ({err.strip()[:120]})", "netlify status"); return
    try:
        rec.account = (json.loads(out).get("siteData") or {}).get("site-name", "netlify")
    except ValueError:
        rec.account = "netlify"
    rc, out, _ = run(["netlify", "env:list", "--json"], cwd=root)
    try:
        names = list(json.loads(out).keys()) if rc == 0 else []      # values are never stored or printed
    except (ValueError, AttributeError):
        names = []
    if rc == 0:
        p_env_names(rec, names, "netlify env:list")


PROWLER_MAP = [
    (r"s3_account_level_public_access_blocks|storage_blob_public_access_level_is_disabled|cloudstorage_bucket_uniform", "CLD-028"),
    (r"s3_bucket_public|cloudstorage_bucket_public_access|storage_.*public", "CLD-001"),
    (r"iam_root_(?:mfa|hardware_mfa)|iam_no_root_access_key", "CLD-007"),
    (r"iam_user_mfa|iam_.*console.*mfa|entra_.*mfa", "CLD-023"),
    (r"iam_rotate_access_key|iam_user_accesskey_unused|iam_sa_.*key.*rotat|iam_key_rotation", "CLD-024"),
    (r"iam_password_policy", "CLD-025"),
    (r"guardduty_is_enabled|securitycenter|defender_ensure_defender", "CLD-026"),
    (r"kms_cmk_rotation|kms_key_rotation|keyvault_key_rotation", "CLD-027"),
    (r"cloudtrail_multi_region|logging_.*audit|monitor_diagnostic", "CLD-009"),
    (r"cloudtrail_log_file_validation", "CLD-033"),
    (r"securitygroup_allow_ingress_from_internet|firewall_.*internet|network_.*internet_access_restricted|cloudsql_instance_public|rds_instance_no_public", "CLD-010"),
    (r"rds_instance_storage_encrypted|.*encrypt", "CLD-002"),
    (r"rds_instance_deletion_protection|rds_instance_backup|cloudsql_.*backup", "CLD-037"),
    (r"ebs_public_snapshot|rds_snapshots_public|ec2_ami_public", "CLD-032"),
    (r"awslambda_function_url_public|cloudfunctions_.*public|cloudrun_.*public", "CLD-039"),
    (r"ecr_repositories_scan|ecr_.*public", "CLD-040"),
    (r"keyvault_recoverable|keyvault_.*purge", "CLD-035"),
]


def p_prowler(rec, root, opts, cloud):
    if not shutil.which("prowler"):
        rec.add("installed", [], "info", "Prowler isn't installed; ask the user before installing it (pip install prowler)", "which prowler"); return
    outdir = root / ".vibe-check" / "live" / f"prowler-{cloud}"
    outdir.mkdir(parents=True, exist_ok=True)
    args = ["prowler", cloud, "--output-formats", "json-ocsf", "--output-directory", str(outdir), "--no-banner"]
    if opts.get("profile") and cloud == "aws":
        args += ["--profile", opts["profile"]]
    if opts.get("project") and cloud == "gcp":
        args += ["--project-ids", opts["project"]]
    run(args, timeout=1800)
    findings = []
    for f in outdir.rglob("*.json"):
        try:
            data = json.loads(f.read_text("utf-8"))
        except ValueError:
            continue
        findings += data if isinstance(data, list) else [data]
    rec.account = cloud
    by_check = {}
    for fd in findings:
        code = ((fd.get("metadata") or {}).get("event_code") or fd.get("check_id") or "").lower()
        status = (fd.get("status_code") or fd.get("status") or "").upper()
        for rx, cid in PROWLER_MAP:
            if re.search(rx, code):
                b = by_check.setdefault(cid, {"FAIL": set(), "PASS": 0})
                if status == "FAIL":
                    b["FAIL"].add(code)
                elif status == "PASS":
                    b["PASS"] += 1
                break
    for cid, b in sorted(by_check.items()):
        rec.add(f"prowler-{cid.lower()}", [cid], "fail" if b["FAIL"] else "pass",
                f"Prowler: failing {', '.join(sorted(b['FAIL'])[:5])}" if b["FAIL"] else f"Prowler: {b['PASS']} passing finding(s)", f"prowler {cloud}")
    if not findings:
        rec.add("results", [], "info", "Prowler produced no results (check its output folder)", f"prowler {cloud}")


PROVIDERS = {"github": ("gh", p_github), "aws": ("aws", p_aws), "gcp": ("gcloud", p_gcp), "azure": ("az", p_azure),
             "firebase": ("firebase", p_firebase), "supabase": ("psql", p_supabase), "vercel": ("vercel", p_vercel),
             "netlify": ("netlify", p_netlify), "prowler-aws": ("prowler", None), "prowler-gcp": ("prowler", None), "prowler-azure": ("prowler", None)}
SIGNED_IN_HINTS = {"aws": ["~/.aws/credentials", "~/.aws/config", "env:AWS_ACCESS_KEY_ID", "env:AWS_PROFILE"],
                   "gcp": ["~/.config/gcloud/active_config", "env:CLOUDSDK_CORE_PROJECT"],
                   "azure": ["~/.azure/azureProfile.json"], "github": ["~/.config/gh/hosts.yml", "env:GH_TOKEN", "env:GITHUB_TOKEN"],
                   "firebase": ["~/.config/configstore/firebase-tools.json"], "supabase": ["env:VIBE_CHECK_DB_URL"],
                   "vercel": ["~/.vercel", "~/Library/Application Support/com.vercel.cli/auth.json", "~/.local/share/com.vercel.cli/auth.json"],
                   "netlify": ["~/.netlify/config.json", "~/Library/Preferences/netlify/config.json"]}


def detect():
    out = []
    for prov, (tool, _) in PROVIDERS.items():
        if prov.startswith("prowler"):
            continue
        installed = bool(shutil.which(tool))
        hints = SIGNED_IN_HINTS.get(prov, [])
        signed = any((os.environ.get(h[4:]) if h.startswith("env:") else Path(os.path.expanduser(h)).exists()) for h in hints)
        out.append((prov, tool, installed, signed))
    return out


def write_summary(vc):
    rows = []
    for f in sorted((vc / "live").glob("*.json")):
        try:
            d = json.loads(f.read_text("utf-8"))
        except ValueError:
            continue
        if not isinstance(d, dict) or "results" not in d:
            continue
        for r in d["results"]:
            rows.append((d["provider"], d.get("account", ""), d.get("time", ""), r))
    icon = {"pass": "✅", "fail": "❌", "check": "❓", "info": "➖"}
    lines = ["# Live account checks (read-only)", "",
             "Written by live.py. Use a result as evidence by copying it exactly: `LIVE: <id> → <summary>`.", "",
             "| | Result id | Checks | Account | Summary |", "|---|---|---|---|---|"]
    for prov, acct, t, r in rows:
        lines.append(f"| {icon.get(r['status'], '')} | `{r['id']}` | {', '.join(r['checks'])} | {acct} | {r['summary']} |")
    (vc / "live" / "summary.md").write_text("\n".join(lines) + "\n", "utf-8")
    return len(rows)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip()); return 0 if argv else 2
    opts = {}
    for flag in ("--run", "--profile", "--project"):
        if flag in argv:
            i = argv.index(flag); opts[flag[2:]] = argv[i + 1]; del argv[i:i + 2]
    consent = "--consent" in argv
    want_detect = "--detect" in argv
    rest = [a for a in argv if not a.startswith("--")]
    root = Path(rest[0] if rest else ".").resolve()
    vc = root / ".vibe-check"
    if want_detect:
        print("Tools on this computer (nothing was read from any account):")
        for prov, tool, inst, signed in detect():
            print(f"  {prov:9} {tool:9} {'installed' if inst else 'not installed':14} {'looks signed in' if (inst and signed) else ''}")
        print("Ask the user, as a choice, before reading any of them: live.py --run <provider> --consent")
        return 0
    prov = opts.get("run")
    if prov not in PROVIDERS:
        print(f"Unknown provider. Use one of: {', '.join(PROVIDERS)}"); return 2
    ans = (vc / "answers.md").read_text("utf-8") if (vc / "answers.md").exists() else ""
    base = prov.split("-")[-1] if prov.startswith("prowler") else prov
    if not consent or not re.search(r"^\s*[-*]?\s*LIVE:\s*" + re.escape(base) + r"\s*:?\s*yes\b", ans, re.M | re.I):
        print(f"NOT RUN: reading the live {base} account needs the user's yes. Ask first, write 'LIVE: {base}: yes' in "
              f".vibe-check/answers.md, then run with --consent.")
        return 1
    rec = Recorder(prov)
    try:
        if prov.startswith("prowler"):
            p_prowler(rec, root, opts, base)
        else:
            PROVIDERS[prov][1](rec, root, opts)
    except Refused as e:
        print(str(e)); return 1
    (vc / "live").mkdir(parents=True, exist_ok=True)
    data = {"provider": prov, "account": rec.account, "consent": True, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "results": rec.results}
    (vc / "live" / f"{prov}.json").write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", "utf-8")
    n = write_summary(vc)
    fails = sum(1 for r in rec.results if r["status"] == "fail")
    print(f"live: read {prov} ({rec.account or 'account'}) read-only: {len(rec.results)} result(s), {fails} failing -> .vibe-check/live/summary.md ({n} in all)")
    for r in rec.results:
        print(f"  {r['status']:5} {r['id']}: {r['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
