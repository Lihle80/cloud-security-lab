# AWS Security Lab

A multi-account AWS security baseline built entirely in Terraform: organization
guardrails, identity, detection, auto-remediation, network segmentation, data
protection, secrets, vulnerability management, and a DevSecOps pipeline that
deploys through GitHub OIDC with no long-lived credentials.

Each numbered directory under `stacks/` is an independent Terraform root with
its own state, applied in order.

---

## Verification status

Honest accounting of what has been checked and how:

| Check | Status |
|---|---|
| `terraform fmt -check -recursive` | passing |
| `terraform validate`, all 10 roots | passing |
| Checkov | 336 passed, 0 failed, all suppressions documented |
| tfsec | 105 passed, 0 findings, 24 documented ignores |
| cfn-guard, SSM Automation documents | 6/6 rules pass |
| `terraform apply` | **not yet run — see [Applying](#applying)** |

Static analysis cannot catch everything. Two real defects were found and fixed
*by* these checks rather than by reading the code, which is the argument for
running them in CI:

- The AFT module declares its own providers, so it cannot take `count`. The
  `count`-based enable flag was invalid and is now a validated variable.
- AFT 1.14 requires AWS provider 6.x against the repo's 5.70 pin, producing an
  unsatisfiable constraint at `init`.

---

## Lab coverage

| # | Topic | Where | Status |
|---|---|---|---|
| 1 | Landing zone, Control Tower, AFT | `control-tower/` | **written, not applied** — see below |
| 2 | Identity Center, SCPs, boundaries, Access Analyzer | `stacks/10-org`, `stacks/20-identity` | complete |
| 3 | Org CloudTrail, GuardDuty, Security Hub, EventBridge→SNS | `stacks/30-detection` | complete |
| 4 | Config rule + SSM Automation auto-remediation | `stacks/40-autoremediate` | complete |
| 5 | Subnet tiers, SG vs NACL, VPC endpoints, flow logs, ALB+WAF | `stacks/50-network` | complete |
| 6 | KMS key policies, cross-account, S3 TLS/SSE-KMS, Backup Vault Lock | `stacks/60-data` | complete |
| 7 | Secrets Manager rotation vs Parameter Store | `stacks/70-secrets` | complete |
| 8 | Inspector (EC2/ECR/Lambda), SSM Patch Manager | `stacks/80-vulnmgmt` | complete |
| 9 | Checkov/tfsec/cfn-guard on PR, deploy via GitHub OIDC | `.github/workflows/` | complete |

### Why item 1 is not applied

A Control Tower landing zone **cannot create its own Log Archive and Audit
accounts** — you pass it the IDs of accounts that already exist. Deploying it
means calling `organizations:CreateAccount` twice, and closing an AWS account
is a 90-day process with no fast undo.

The guardrails Control Tower would provide — OU structure, SCPs, org CloudTrail,
delegated-admin GuardDuty and Security Hub — are all implemented directly in
`stacks/10-org` and `stacks/30-detection`. Control Tower packages them
differently; it does not add a control that is otherwise missing.

The code is complete and reviewed. [`control-tower/README.md`](control-tower/README.md)
covers what to change before applying, and why **proactive controls are
CloudFormation Hooks and therefore never fire for a Terraform apply** — which
is why `cfn-guard` runs in the pipeline instead.

---

## Prerequisites

1. **Organization management account.** `stacks/10-org` and `stacks/30-detection`
   manage SCPs and an organization trail, which only the management account can do.

2. **Trusted access and policy types.** Not expressible in Terraform — there is
   no resource for `enable-aws-service-access`, and importing
   `aws_organizations_organization` would put `DeleteOrganization` inside
   `terraform destroy`. Run once:

   ```bash
   ./scripts/00-prereqs.sh
   ```

3. **IAM Identity Center**, if you want `stacks/20-identity`'s permission sets.
   Terraform **cannot** create the instance — only an `aws_ssoadmin_instances`
   data source exists. Enable it once in the console, then set
   `enable_identity_center = true`. The stack's permission boundary and
   boundary-constrained role work without it.

4. **Tooling.** Terraform >= 1.11 (for S3 native state locking via
   `use_lockfile`), plus `checkov`, `tfsec` and `cfn-guard` for local scanning.

---

## Applying

Order matters. `40-autoremediate` turns on the Config recorder that most
Security Hub controls depend on, so applying `30-detection` first and stopping
leaves Security Hub reporting "No data" for much of its coverage.

```bash
# 0. State backend. Local state, by necessity — it creates the bucket
#    every other stack uses as a backend.
terraform -chdir=stacks/00-bootstrap init
terraform -chdir=stacks/00-bootstrap apply

# Generate backend.hcl (keeps the account ID out of git)
./scripts/backend.sh

# 1-8. The rest, in order.
for s in 10-org 20-identity 30-detection 40-autoremediate \
         50-network 60-data 70-secrets 80-vulnmgmt; do
  terraform -chdir="stacks/$s" init -backend-config=../../backend.hcl
  terraform -chdir="stacks/$s" apply
done
```

Run `./scripts/validate-all.sh` first — it runs locally exactly what the PR
pipeline runs, and needs no credentials.

### Expensive things are off by default

Every costly resource is behind a variable defaulting to `false`, with the
reason in its description:

| Variable | Stack | Default | Monthly if enabled |
|---|---|---|---|
| `enable_interface_endpoints` | 50-network | `false` | ~$70 (6 endpoints × 2 AZ) |
| `enable_rds` | 70-secrets | `false` | ~$15 |
| `enable_unused_access_analyzer` | 10-org | `false` | per-role pricing |
| `enable_vault_lock` | 60-data | `false` | storage commitment |
| `create_demo_bucket` | 40-autoremediate | `false` | negligible |

Enabled by default: a single NAT gateway (~$32), the ALB (~$16), the WAF web
ACL (~$5 + $1/rule group), Security Hub standards (single-digit dollars), and
the Config recorder (cents in a small account). Set `enable_nat_gateway=false`
and `enable_alb=false` to get that close to zero.

**`terraform destroy` the stacks in reverse order when you are done.**

---

## Deliberate decisions worth defending

Things a reviewer should expect to question.

**The CI apply role holds `AdministratorAccess`.** This lab provisions across
Organizations, Identity Center, KMS, Config, GuardDuty, Security Hub, Inspector
and Backup; a hand-written least-privilege policy would be larger than the lab
and would break on every addition. The control that matters is the OIDC trust
policy, which matches `repo:<owner>/<repo>:ref:refs/heads/main` **exactly** —
no wildcard — so the role is unassumable from a branch, tag, pull request or
fork. The plan role is separately `ReadOnlyAccess`.

**The permission boundary starts at `Action: "*"`.** Scanners flag this, and it
is correct. A boundary is a ceiling, not a grant: effective permissions are
(identity policy ∩ boundary). A boundary that enumerated allowed actions would
silently block anything omitted and need editing whenever AWS ships a service.
The security is in the `Deny` statements, which no identity policy can override
— including one that forces every principal the holder creates to carry the
same boundary, making the restriction transitive.

**KMS key policies use `Resource: "*"`.** In a key policy that string means
"this key". There is no other legal value; an ARN is rejected by the API. Three
Checkov checks can never pass on a correct key policy.

**Vault Lock defaults to governance, not compliance.** Compliance mode is
irreversible once the grace period elapses — not removable by you, the root
user, or AWS Support — and you pay for the retained storage for the full term.
In a lab that means a resource you cannot clean up for up to a year.

**SCPs are not attached to the organization root by default.**
`attach_scps_to_root` is `false`. SCPs never apply to the management account, so
attaching at root cannot lock you out of it, but it does apply immediately to
every existing member account, including ones this lab did not create.

**Config and log buckets use SSE-S3, not a CMK.** They deliver enormous numbers
of small objects, where per-object KMS calls cost more than the storage. ALB
access logging does not support a customer-managed key at all — delivery fails
silently and the bucket just stays empty.

**The ALB serves plain HTTP when no certificate is set.** This finding is
correct and accepted only because the lab has no domain. Set `certificate_arn`
and it becomes a 301 plus an HTTPS listener with a TLS 1.3/1.2 policy.

---

## Testing

```bash
./scripts/validate-all.sh              # fmt, validate, checkov, tfsec, cfn-guard
./scripts/guardduty-sample-findings.sh # exercise EventBridge -> SNS
./scripts/test-remediation.sh          # prove the auto-remediation loop closes
```

`test-remediation.sh` **deliberately makes an S3 bucket publicly readable** —
the only way to make the Config rule evaluate `NON_COMPLIANT`. It refuses to
run against any bucket but the throwaway fixture, requires typed confirmation,
and re-blocks the bucket on every exit path. No Terraform in this repo ever
creates a public bucket.

See [`docs/TESTING.md`](docs/TESTING.md) for what each test proves and the
failure modes worth knowing.

---

## Repository layout

```
stacks/
  00-bootstrap/      state backend (S3 + native locking), GitHub OIDC roles
  10-org/            OUs, 4 SCPs, Access Analyzer
  20-identity/       permission sets, groups, permission boundary
  30-detection/      org CloudTrail, GuardDuty, Security Hub, EventBridge→SNS
  40-autoremediate/  Config recorder, 5 rules, SSM Automation remediation
  50-network/        3 subnet tiers, SG vs NACL, endpoints, flow logs, ALB+WAF
  60-data/           KMS key policies, S3 TLS/SSE-KMS, Backup + Vault Lock
  70-secrets/        RDS-managed rotation vs Parameter Store SecureString
  80-vulnmgmt/       Inspector, Patch Manager baseline and windows
control-tower/
  landing-zone/      Control Tower landing zone and controls (not applied)
  aft/               Account Factory for Terraform (not applied)
policies/
  terraform-plan.guard   cfn-guard rules run against `terraform show -json`
  ssm-document.guard     cfn-guard rules for SSM Automation documents
scripts/             prerequisites, backend generation, tests
.github/workflows/   PR plan + scan, apply on merge via OIDC
```

---

## Pipeline

`terraform-plan.yml` on every PR: `fmt`, `validate` across all roots, then
Checkov, tfsec and cfn-guard in parallel, then `plan` per stack with the result
posted as a PR comment. A single `gate` job aggregates them so branch
protection needs one required check.

`terraform-apply.yml` on merge to `main`: applies a **saved plan file**, so the
approved change is the change that lands. Gated on a GitHub Environment named
`production` with a required reviewer, and `max-parallel: 1` because the stacks
are ordered.

Both authenticate with `id-token: write` and
`aws-actions/configure-aws-credentials` — there are no AWS access keys in this
repo, in GitHub secrets, or anywhere else.

Set these repository variables after applying `00-bootstrap`:

| Variable | Value |
|---|---|
| `AWS_PLAN_ROLE_ARN` | `gha_plan_role_arn` output |
| `AWS_APPLY_ROLE_ARN` | `gha_apply_role_arn` output |
| `TF_STATE_BUCKET` | `state_bucket` output |
