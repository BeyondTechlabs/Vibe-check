"""Fake aws, gcloud, az, gh, firebase, vercel, netlify and psql commands for testing live.py offline.

Each fake answers the read-only commands live.py uses with canned, deliberately insecure settings, and fails loudly
if it is ever asked to change anything (which live.py's allow-list must prevent).
"""
import os
import stat
from pathlib import Path

COMMON = r'''#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
s = " ".join(a)
def out(x): print(json.dumps(x)); sys.exit(0)
def fail(msg, rc=1): sys.stderr.write(msg); sys.exit(rc)
for w in ("delete", "put-", "create", "update", "rm ", "deploy", "-X"):
    if w in s.split("--output")[0] and "describe" not in s and "get-" not in s.split()[1:2][0:1] and False:
        pass
'''

FAKES = {
"aws": COMMON + r'''
if "put-" in s or " rm " in s or "delete" in s: fail("WRITE ATTEMPTED", 99)
if "sts get-caller-identity" in s: out({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dev"})
if "s3control get-public-access-block" in s: fail("NoSuchPublicAccessBlockConfiguration", 254)
if "s3api list-buckets" in s: out({"Buckets": [{"Name": "uploads-prod"}, {"Name": "site-assets"}]})
if "get-bucket-policy-status" in s: out({"PolicyStatus": {"IsPublic": "uploads-prod" in s}})
if "iam get-account-summary" in s: out({"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}})
if "iam list-users" in s: out({"Users": [{"UserName": "alice"}, {"UserName": "ci-bot"}]})
if "get-login-profile" in s: out({"LoginProfile": {}}) if "alice" in s else fail("NoSuchEntity", 254)
if "list-mfa-devices" in s: out({"MFADevices": []})
if "list-access-keys" in s: out({"AccessKeyMetadata": [{"Status": "Active", "CreateDate": "2023-01-01T00:00:00Z"}]} if "ci-bot" in s else {"AccessKeyMetadata": []})
if "get-account-password-policy" in s: fail("NoSuchEntity", 254)
if "cloudtrail describe-trails" in s: out({"trailList": []})
if "guardduty list-detectors" in s: out({"DetectorIds": []})
if "describe-security-groups" in s: out({"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]})
if "rds describe-db-instances" in s: out({"DBInstances": [{"DBInstanceIdentifier": "main", "PubliclyAccessible": True, "StorageEncrypted": True, "DeletionProtection": False, "BackupRetentionPeriod": 7}]})
if "describe-snapshots" in s: out({"Snapshots": []})
if "kms list-keys" in s: out({"Keys": []})
if "budgets describe-budgets" in s: out({"Budgets": []})
if "lambda list-functions" in s: out({"Functions": []})
fail("unknown aws command: " + s, 2)
''',
"gh": COMMON + r'''
if "-X" in a or "delete" in s: fail("WRITE ATTEMPTED", 99)
if a[:2] == ["repo", "view"]: out({"nameWithOwner": "acme/shop", "defaultBranchRef": {"name": "main"}, "visibility": "PUBLIC", "owner": {"login": "acme"}})
if a[:1] == ["api"]:
    p = a[1]
    if p == "repos/acme/shop": out({"owner": {"type": "Organization"}, "security_and_analysis": {"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "disabled"}}})
    if p.endswith("/protection"): fail("gh: Branch not protected (HTTP 404)", 1)
    if p.endswith("/rulesets"): out([])
    if p.endswith("/actions/permissions/workflow"): out({"default_workflow_permissions": "write"})
    if p.endswith("/vulnerability-alerts"): sys.exit(0)
    if "dependabot/alerts" in p: out([{"security_advisory": {"severity": "high"}}, {"security_advisory": {"severity": "low"}}])
    if p == "orgs/acme": out({"two_factor_requirement_enabled": False})
fail("unknown gh command: " + s, 2)
''',
"psql": COMMON + r'''
q = a[a.index("-c") + 1].lower()
if not q.startswith("select"): fail("WRITE ATTEMPTED", 99)
if "relrowsecurity" in q: print("orders\nprofiles"); sys.exit(0)
if "pg_policies" in q: print("orders.read_all"); sys.exit(0)
if "relkind = 'v'" in q: print(""); sys.exit(0)
if "storage.buckets" in q: print("avatars"); sys.exit(0)
fail("unknown query", 2)
''',
"vercel": COMMON + r'''
if a[:1] == ["whoami"]: print("acme"); sys.exit(0)
if a[:2] == ["env", "ls"]: print(" name                          value     environments\n NEXT_PUBLIC_SUPABASE_URL      Encrypted Production\n NEXT_PUBLIC_STRIPE_SECRET_KEY Encrypted Production\n DATABASE_URL                  Encrypted Production"); sys.exit(0)
fail("unknown vercel command: " + s, 2)
''',
}

FAKES["gcloud"] = COMMON + r"""
if any(w in a for w in ("delete", "update", "create")): fail("WRITE ATTEMPTED", 99)
if a[:3] == ["config", "get-value", "project"]: print("acme-prod"); sys.exit(0)
if a[:2] == ["projects", "get-iam-policy"]: out({"bindings": [{"role": "roles/owner", "members": ["user:a@x.com", "user:b@x.com"]}, {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]})
if a[:3] == ["iam", "service-accounts", "list"]: out([{"email": "app@acme-prod.iam.gserviceaccount.com"}])
if a[:4] == ["iam", "service-accounts", "keys", "list"]: out([{"name": "k1"}])
if a[:3] == ["storage", "buckets", "list"]: out([{"name": "acme-uploads", "public_access_prevention": "inherited"}])
if a[:3] == ["storage", "buckets", "get-iam-policy"]: out({"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]})
if a[:3] == ["compute", "firewall-rules", "list"]: out([{"name": "allow-db", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["5432"]}]}])
if a[:3] == ["sql", "instances", "list"]: out([{"name": "main", "settings": {"ipConfiguration": {"authorizedNetworks": []}, "backupConfiguration": {"enabled": False}}}])
if a[:3] == ["services", "api-keys", "list"]: out([{"displayName": "Browser key", "uid": "abc123"}])
fail("unknown gcloud command: " + s, 2)
"""
FAKES["az"] = COMMON + r"""
if any(w in a for w in ("delete", "update", "create", "set")): fail("WRITE ATTEMPTED", 99)
if a[:2] == ["account", "show"]: out({"id": "11111111-2222-3333-4444-555566667777"})
if a[:3] == ["storage", "account", "list"]: out([{"name": "acmefiles", "allowBlobPublicAccess": True, "minimumTlsVersion": "TLS1_0", "enableHttpsTrafficOnly": True}])
if a[:3] == ["network", "nsg", "list"]: out([{"name": "web", "securityRules": [{"name": "rdp", "direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRange": "3389"}]}])
if a[:3] == ["security", "pricing", "list"]: out({"value": [{"name": "VirtualMachines", "pricingTier": "Free"}]})
if a[:2] == ["keyvault", "list"]: out([{"name": "acme-kv", "properties": {"enablePurgeProtection": None}}])
if a[:2] == ["webapp", "list"]: out([])
fail("unknown az command: " + s, 2)
"""
FAKES["prowler"] = COMMON + r"""
import pathlib
d = pathlib.Path(a[a.index("--output-directory") + 1]); d.mkdir(parents=True, exist_ok=True)
(d / "vc.ocsf.json").write_text(json.dumps([
  {"metadata": {"event_code": "guardduty_is_enabled"}, "status_code": "FAIL"},
  {"metadata": {"event_code": "iam_root_mfa_enabled"}, "status_code": "PASS"},
  {"metadata": {"event_code": "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"}, "status_code": "FAIL"}]))
sys.exit(0)
"""


def install(dirpath: Path):
    dirpath.mkdir(parents=True, exist_ok=True)
    for name, body in FAKES.items():
        f = dirpath / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dirpath


def env_with(dirpath: Path, **extra):
    e = dict(os.environ, PATH=str(dirpath) + os.pathsep + os.environ.get("PATH", ""))
    e.update(extra)
    return e
