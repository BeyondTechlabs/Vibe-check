# Cloud infrastructure (AWS, Google Cloud, Azure, Kubernetes)

Load this file when the app runs on AWS, Google Cloud, Azure, DigitalOcean, Hetzner or similar, or uses Kubernetes, Terraform, Pulumi, CloudFormation or Docker Compose in production. Platform apps (Vercel, Netlify, Supabase, Firebase, Cloudflare) are covered in `platforms.md`. Read the IaC files and deployment configs. If the user has the cloud CLI logged in, run **read-only** commands only (`aws s3api get-bucket-policy-status`, `gcloud … describe`, `az … show`), never anything that changes resources.

## Storage
- [ ] 🔴 CLD-001 **No public buckets with private data:** S3 Block Public Access on (account and bucket), GCS uniform access without `allUsers`/`allAuthenticatedUsers`, Azure containers not set to public access. Public assets live in a separate, clearly public bucket.
- [ ] 🔴 CLD-002 **Cloud storage and disks encrypted** (buckets, databases, disks and snapshots) (default encryption on, customer-managed keys for sensitive data if required).
- [ ] 🟡 CLD-003 **Versioning and lifecycle rules** on important buckets, so deleted or overwritten files can be recovered and old data expires on schedule.
- [ ] 🟡 CLD-004 **Signed URLs** with short expiry for private files, never long-lived public links.

## Identity and access (IAM)
- [ ] 🔴 CLD-005 **No wildcard permissions** for app roles (`"Action": "*"`, `"Resource": "*"`, Owner/Editor roles for service accounts).
- [ ] 🔴 CLD-006 **No long-lived access keys in code or CI:** use instance roles, workload identity or OIDC for CI. Old keys are rotated or deleted.
- [ ] 🔴 CLD-007 **Root/owner account locked down:** MFA on, no access keys, used only for break-glass. Billing alerts set.
- [ ] 🟡 CLD-008 **Separate accounts or projects** for production and non-production.
- [ ] 🟡 CLD-009 **Cloud audit logs on** (CloudTrail, Cloud Audit Logs, Azure Activity Log) and kept for at least 90 days.

## Network
- [ ] 🔴 CLD-010 **Databases, caches and admin ports aren't open to the internet:** no `0.0.0.0/0` on 5432, 3306, 27017, 6379, 9200, 22 or RDP. Databases are in private subnets.
- [ ] 🔴 CLD-011 **TLS on every public endpoint** (load balancers, API gateways, CDNs), with HTTP redirected and old TLS versions disabled.
- [ ] 🟡 CLD-012 **SSH access** by key only (or through a bastion or session manager), no password login, no root login.
- [ ] 🟡 CLD-013 **WAF or rate limiting** at the edge for public APIs and login.

## Kubernetes and containers
- [ ] 🔴 CLD-014 **Secrets aren't in images or plain manifests:** use Kubernetes Secrets with encryption at rest, or an external secret manager. `docker history` shows no secrets.
- [ ] 🔴 CLD-015 **Containers don't run as root or privileged** unless required (`runAsNonRoot`, no `privileged: true`, read-only root filesystem where possible).
- [ ] 🟡 CLD-016 **Resource requests and limits** set, so one service can't starve others.
- [ ] 🟡 CLD-017 **Images from trusted registries,** pinned by digest or version (not `latest`), and scanned for vulnerabilities.
- [ ] 🟡 CLD-018 **The Kubernetes API and dashboards aren't public,** and RBAC follows least privilege.

## Infrastructure as Code
- [ ] 🟡 CLD-019 **IaC scanned** for misconfigurations (e.g. `tfsec`, `checkov`, `trivy config`), and state files (Terraform state) stored privately and encrypted, since they contain secrets.
- [ ] 🟡 CLD-020 **Changes go through review and CI,** not manual console edits (drift is detected).
- [ ] 🟡 CLD-021 **Backups and snapshots are automatic** for databases and volumes, and a restore has been tested (see `devops.md`).
- [ ] 🟢 CLD-022 **Cost controls:** budgets and alerts, auto-scaling limits, and no forgotten resources (unused instances, load balancers, IPs, snapshots).

## Account settings (read live with `live.py` when the user allows; otherwise from IaC files or `CHECK:`)
- [ ] 🔴 CLD-023 **MFA on every human user:** every IAM user with a console password (AWS), every human principal (Google Cloud, Azure) uses MFA or signs in through SSO that enforces it.
- [ ] 🟡 CLD-024 **No old or unused access keys:** user access keys and service account keys older than 90 days are rotated, and unused ones are deleted.
- [ ] 🟡 CLD-025 **A strong password policy, or SSO only:** cloud console passwords have a length and reuse policy, or people sign in only through SSO.
- [ ] 🔴 CLD-026 **Threat detection is on:** AWS GuardDuty, Google Security Command Center or Microsoft Defender for Cloud is enabled for production, and someone reads its findings.
- [ ] 🟡 CLD-027 **Customer-managed keys rotate:** KMS / Cloud KMS / Key Vault keys used for data have automatic rotation on.
- [ ] 🔴 CLD-028 **Public access is blocked at the account level:** S3 account-wide Block Public Access, Google Cloud public access prevention, Azure `allowBlobPublicAccess: false`, so one wrong bucket setting can't expose data.
- [ ] 🟡 CLD-029 **Few owners and admins:** a handful of named people have owner/admin roles; no shared or personal email accounts own production.
- [ ] 🔴 CLD-030 **No public principals:** no IAM binding or policy grants `allUsers`, `allAuthenticatedUsers`, `*` or `AllUsers` access, except to assets meant to be public.
- [ ] 🟡 CLD-031 **Workloads don't use downloaded keys:** services use attached roles, workload identity or managed identities rather than long-lived key files.
- [ ] 🔴 CLD-032 **Snapshots and machine images aren't public:** database snapshots, disk snapshots and images are shared only with named accounts.
- [ ] 🟡 CLD-033 **Audit logs are kept and protected:** log file validation on (AWS), retention long enough to investigate an incident, and only a few people can delete them.
- [ ] 🟡 CLD-034 **Storage requires modern TLS:** minimum TLS 1.2 on storage accounts and buckets (Azure `minimumTlsVersion`, an S3 policy denying non-TLS requests).
- [ ] 🟡 CLD-035 **Secret stores can't be wiped by mistake:** Key Vault soft delete and purge protection; Secrets Manager / Secret Manager recovery windows.
- [ ] 🟡 CLD-036 **Load balancers use a modern TLS policy** and redirect HTTP to HTTPS.
- [ ] 🟡 CLD-037 **Databases are protected from loss:** automated backups with a retention period, and deletion protection on production databases.
- [ ] 🟡 CLD-038 **Production doesn't live in the default network,** and network flow logs are on where incidents would need them.
- [ ] 🟡 CLD-039 **Serverless functions aren't open to anyone** (Lambda function URLs with `AuthType NONE`, unauthenticated Cloud Functions/Run, anonymous Azure Functions) unless they're meant to be public and check their callers.
- [ ] 🟡 CLD-040 **Container registries are private** and scan images for known vulnerabilities.
- [ ] 🟡 CLD-041 **Alerts for risky account events:** root/owner sign-ins, IAM policy changes and disabled logging alert a person.
- [ ] 🟡 CLD-042 **Function environment variables hold no plain secrets:** Lambda, Cloud Functions and App Service settings reference a secret store instead.
- [ ] 🟡 CLD-043 **Kubernetes RBAC is tight:** no `cluster-admin` for default or workload service accounts, and namespaces separate teams or apps.
- [ ] 🟡 CLD-044 **Kubernetes network policies** restrict which pods can talk to which, and to the internet.
- [ ] 🟡 CLD-045 **Kubernetes control-plane audit logs are on** and kept.

