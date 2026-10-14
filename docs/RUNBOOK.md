# Runbook

Operational procedures for this lab, and the production hardening steps
deliberately left out of it.

---

## Apply order and why it matters

```
00-bootstrap  ->  10-org  ->  20-identity  ->  30-detection
              ->  40-autoremediate  ->  50-network  ->  60-data
              ->  70-secrets  ->  80-vulnmgmt
```

The ordering is not cosmetic:

- **`00-bootstrap` uses local state** by necessity — it creates the bucket
  every other stack uses as a backend.
- **`40-autoremediate` before meaningful Security Hub results.** Most FSBP and
  CIS controls are implemented as Config rules underneath. Without the
  recorder, a large share of controls report "No data" rather than failing, so
  `30-detection` looks cleaner than it is.
- **`50-network` before `70-secrets`.** The database is placed in the isolated
  subnets and discovered by tag; applying `70-secrets` with `enable_rds = true`
  first will fail to find them.
- **`60-data` before `70-secrets`.** The secrets stack reads
  `alias/aws-security-lab-data` via data source. That lookup is not gated, so
  it fails outright if the key does not exist.

---

## Backend configuration

`kms_key_id` is **required**, not optional:

```hcl
# backend.hcl — generated, gitignored
bucket     = "aws-security-lab-tfstate-<account-id>"
region     = "us-west-2"
kms_key_id = "arn:aws:kms:us-west-2:<account-id>:key/<key-id>"
```

With `encrypt = true` and no `kms_key_id`, the S3 backend requests SSE-S3
(AES256), which the state bucket policy rejects:

```
Error acquiring the state lock
AccessDenied: not authorized to perform: s3:PutObject on
".../terraform.tfstate.tflock" with an explicit deny in a resource-based policy
```

Generate it with `./scripts/backend.sh`, which derives the bucket name from
`sts get-caller-identity` so the account ID never enters git.

---

## Moving an account between OUs

**Not managed in Terraform, on purpose.** The only handle Terraform has on an
existing account is `aws_organizations_account`, which must be imported first
and — critically — attempts to **close the account** on destroy. That turns
`terraform destroy` into a data-loss event.

Do it with the CLI:

```bash
# Find the current parent
aws organizations list-parents --child-id <account-id>

# Target OU
terraform -chdir=stacks/10-org output ou_ids

aws organizations move-account \
  --account-id <account-id> \
  --source-parent-id <current-parent-id> \
  --destination-parent-id <target-ou-id>
```

**This changes which SCPs apply immediately.** Before moving an account into
`Workloads/*` or `Sandbox`, read `stacks/10-org/scps.tf` — those OUs carry
`deny-unapproved-regions`, which will break anything operating outside
`us-west-2` and `us-east-1`.

Verify what now applies:

```bash
aws organizations list-policies-for-target \
  --target-id <account-id> --filter SERVICE_CONTROL_POLICY
```

---

## Stale state locks

An interrupted apply leaves a lock file. The error names the ID:

```
Lock Info:
  ID:        afde26a5-f884-b70f-3ec7-1d979049ef56
  Operation: OperationTypeApply
  Who:       user@host
```

Confirm nothing is genuinely running, then:

```bash
terraform -chdir=stacks/<stack> force-unlock -force <lock-id>
```

Check `Who` and `Created` first. Force-unlocking a live apply lets two
processes write the same state and corrupt it.

---

## Reserved name prefixes

Three services reject names beginning with `aws`. Hitting this three times in
one project is why it is worth writing down:

| Service | Rule | Error |
|---|---|---|
| SSM documents | no `aws-`, `amazon`, `amzn` | `ValidationException: Invalid document name` |
| Parameter Store | no `aws`, `ssm` (case-insensitive) | `AccessDeniedException: No access to reserved parameter name` |
| Patch baselines | no `AWS-`, `AWS:` | `cannot starts with: AWS- or AWS:` |

The project slug is `aws-security-lab`, so each of these uses
`replace(var.project, "/^aws-/", "")`. If you rename the project to something
not starting with `aws`, those `replace` calls become no-ops and can stay.

Two more naming constraints encountered:

- **Security group rule descriptions** allow only
  `a-zA-Z0-9 . _ - : / ( ) # , @ [ ] + = & ; { } ! $ *`. No apostrophes.
- **WAF log destinations** must begin with `aws-waf-logs-`. This one *requires*
  the prefix the others forbid.

---

## Production hardening left out of the lab

Each of these is a deliberate omission, flagged in the code where it applies.

### S3 Object Lock on the CloudTrail bucket

The single most valuable addition. Object Lock in compliance mode makes
delivered log files immutable, so an attacker with full S3 access still cannot
erase the record of what they did. Versioning and log file validation (both
enabled) let you *detect* tampering; Object Lock prevents it.

Not enabled here because it must be set **at bucket creation** and cannot be
added later — you would have to recreate the bucket and migrate the logs.

```hcl
resource "aws_s3_bucket" "trail" {
  bucket              = local.trail_bucket_name
  object_lock_enabled = true   # creation-time only
}

resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail[0].id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 400
    }
  }
}
```

Note the same irreversibility warning as Backup Vault Lock: compliance mode
cannot be shortened or removed, by anyone.

### Access logging on the protected bucket

Declined repo-wide to avoid a log bucket per bucket, but
`stacks/60-data` holds the data the whole stack exists to protect. That one
genuinely warrants it in production:

```hcl
resource "aws_s3_bucket_logging" "protected" {
  bucket        = aws_s3_bucket.protected.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "protected/"
}
```

CloudTrail S3 **data events** are the better answer if you only need the audit
trail — they capture the calling principal, which server access logs do not
reliably. They are billed per event, which is why they are off here.

### Deletion protection

| Resource | Lab setting | Production |
|---|---|---|
| `aws_lb` | `enable_deletion_protection = false` | `true` |
| `aws_db_instance` | `deletion_protection = false` | `true` |
| `aws_db_instance` | `skip_final_snapshot = true` | `false` |
| `aws_s3_bucket` (state) | `force_destroy = false` | plus `prevent_destroy` |

### Least privilege for the CI apply role

`stacks/00-bootstrap/github_oidc.tf` attaches `AdministratorAccess`. The
documented reasoning is in the README; the mitigation is an exact-match OIDC
trust policy. For production, generate a scoped policy from observed usage:

```bash
aws accessanalyzer start-policy-generation \
  --policy-generation-details principalArn=arn:aws:iam::<acct>:role/aws-security-lab-gha-apply \
  --cloud-trail-details '{...}'
```

Let the lab run a full apply cycle first so CloudTrail has the complete action
set, then generate.

### Dedicated Security account

GuardDuty and Security Hub currently run from the management account because
this lab has only two accounts. Production guidance is a dedicated Security
account in the Security OU, set via `delegated_admin_account_id`.

Note the asymmetry: **GuardDuty accepts the management account** as delegated
administrator, **Security Hub does not**. That is why
`aws_guardduty_organization_admin_account` is unconditional while the Security
Hub equivalent stays gated on an explicit member account ID.

---

## Teardown

Reverse order, because of the dependencies above:

```bash
for s in 80-vulnmgmt 70-secrets 60-data 50-network \
         40-autoremediate 30-detection 20-identity 10-org; do
  terraform -chdir="stacks/$s" destroy -auto-approve
done

terraform -chdir=stacks/00-bootstrap destroy -auto-approve
```

To cut most of the cost without tearing everything down, destroy only the
network stack — it holds the NAT gateway, ALB and WAF:

```bash
terraform -chdir=stacks/50-network destroy
```

### Things that will not destroy cleanly

- **Backup vault with recovery points.** `force_destroy = false` means destroy
  fails rather than silently deleting backups. Delete recovery points first, or
  accept the failure and clean up by hand.
- **Vault Lock in compliance mode.** Cannot be removed. The vault survives
  until every recovery point's retention expires, and you keep paying. This is
  why `enable_vault_lock` defaults to `false`.
- **KMS keys** enter a 7-day pending-deletion window rather than disappearing.
  The alias is freed immediately, so a re-apply works.
- **S3 buckets with objects.** The state, trail, config and protected buckets
  use `force_destroy = false` deliberately. Empty them first:
  ```bash
  aws s3 rm "s3://<bucket>" --recursive
  ```
  For a versioned bucket you must also delete the version markers — `rm
  --recursive` leaves them and the delete still fails.
- **SCPs** must be detached before deletion; Terraform handles the ordering,
  but a partially-destroyed `10-org` can leave attachments behind.
- **Organization trail.** Destroying `30-detection` removes the org trail.
  Confirm you are not relying on it for audit retention — the S3 objects
  survive, but new events stop being recorded.

### Pre-existing resources this lab must not touch

- `IsengardTrail-DO-NOT-DELETE` — created outside this repo, never managed by
  it. The lab creates a separate org trail alongside it.
- The **existing GuardDuty detector**. A region permits only one, so
  `create_guardduty_detector` defaults to `false` and the stack reads the
  existing detector by data source. Destroying the stack does not delete it,
  but it *does* remove the protection-plan features and org configuration the
  stack enabled on it.
- VPCs `172.31.0.0/16` (default) and `10.42.0.0/16`. The lab uses
  `10.20.0.0/16` to stay clear of both.

---

## Drift

```bash
for s in stacks/*/; do
  echo "== $s"
  terraform -chdir="$s" plan -detailed-exitcode -input=false >/dev/null 2>&1
  case $? in
    0) echo "   no drift" ;;
    2) echo "   DRIFT" ;;
    *) echo "   plan failed" ;;
  esac
done
```

Expected sources of benign drift:

- **GuardDuty detector features** — if someone toggles a protection plan in the
  console, the stack will want to set it back.
- **Security Hub controls** — `auto_enable_controls = true` means AWS adds new
  controls to enabled standards over time. This shows as drift in the standards
  subscription and should be accepted.
- **Access Analyzer findings** are not state; they will never show as drift.
