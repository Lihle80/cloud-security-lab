# Testing

What each test actually proves, how to run it, and the failure modes worth
recognising. Results below are from a real run against a live AWS account in
`us-west-2`.

---

## Static checks — no credentials needed

```bash
./scripts/validate-all.sh
```

Runs `terraform fmt`, `terraform validate` across every root, then Checkov,
tfsec and cfn-guard. This is exactly what the PR pipeline runs, so a clean
local run means a clean CI run.

`control-tower/aft` is skipped by default because `init` downloads the AFT
module tree and takes several minutes. Include it with `VALIDATE_AFT=1`.

**What it proves:** syntax, types, and policy compliance.

**What it does not prove:** anything about AWS's actual behaviour. Nine of the
eleven bugs in this repo's history passed every check above and only surfaced
on `apply`. Treat a green scan as necessary, not sufficient.

---

## ALB and WAF

```bash
ALB=$(terraform -chdir=stacks/50-network output -raw alb_dns_name)

# Benign request
curl -s -o /dev/null -w "%{http_code}\n" "http://$ALB/"

# SQL injection attempt
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://$ALB/?id=1%27%20OR%20%271%27=%271%27%20UNION%20SELECT%20NULL,version()--"
```

| Request | Expected | Verified |
|---|---|---|
| Benign | `200` | `200`, body `aws-security-lab: request reached the ALB through WAF` |
| SQLi | `403` | `403` |

**What it proves:** the web ACL is associated with the ALB and
`AWSManagedRulesSQLiRuleSet` is in blocking mode, not count mode.

**Failure modes:**

- **Both return 200** — the web ACL exists but is not associated. Check
  `aws wafv2 list-resources-for-web-acl --web-acl-arn <arn> --resource-type APPLICATION_LOAD_BALANCER`.
- **Both return 403** — you are being blocked by the IP reputation list or the
  rate limit, not the SQLi rule. Check the `ip-reputation` and `rate-limit`
  CloudWatch metrics.
- **Connection timeout** — `alb_allowed_cidrs` does not include your address,
  or the public NACL is denying. Remember the NACL denies inbound 22 and 3389
  at rules 10 and 20 before any allow is evaluated.

Which rule fired:

```bash
aws logs tail aws-waf-logs-aws-security-lab --since 5m --format short
```

---

## S3 encryption enforcement

The important part is testing **three** paths, not two. The third is the one
that breaks.

```bash
B=$(terraform -chdir=stacks/60-data output -raw protected_bucket)
K=$(terraform -chdir=stacks/60-data output -raw data_key_arn)
echo test > /tmp/t.txt

# 1. Wrong algorithm — must be denied
aws s3api put-object --bucket "$B" --key t1 --body /tmp/t.txt \
  --server-side-encryption AES256

# 2. Correct algorithm and key — must be allowed
aws s3api put-object --bucket "$B" --key t2 --body /tmp/t.txt \
  --server-side-encryption aws:kms --ssekms-key-id "$K"

# 3. No encryption header at all — must ALSO be allowed
aws s3api put-object --bucket "$B" --key t3 --body /tmp/t.txt

# 4. ...and must still land as SSE-KMS with the right key
aws s3api head-object --bucket "$B" --key t3 \
  --query '{Encryption:ServerSideEncryption,Key:SSEKMSKeyId}'
```

| Case | Expected | Verified |
|---|---|---|
| 1 — AES256 | `AccessDenied` | `AccessDenied` |
| 2 — correct CMK | allowed | allowed |
| 3 — no header | **allowed** | allowed |
| 4 — stored encryption | `aws:kms` + correct CMK | confirmed |

**Why case 3 matters.** The obvious policy — `StringNotEquals` on
`s3:x-amz-server-side-encryption` with no `Null` guard — denies case 3,
because IAM treats an absent key as "not equal". That breaks every plain
`aws s3 cp` and most SDK defaults, while adding no security: default bucket
encryption already guarantees SSE-KMS with the correct CMK.

This exact bug deadlocked the state bucket in `00-bootstrap`, where it
prevented Terraform writing `terraform.tfstate.tflock` and made the backend
unusable. If you copy an encryption-enforcement policy from anywhere, test
case 3.

Clean up:

```bash
for k in t2 t3; do aws s3api delete-object --bucket "$B" --key "$k"; done
```

---

## GuardDuty → EventBridge → SNS

```bash
./scripts/guardduty-sample-findings.sh
```

Creates four synthetic findings spanning severities. Safe: nothing real is
touched, and they auto-archive.

The authoritative check is whether the rule fired, not whether findings
exist:

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/Events --metric-name TriggeredRules \
  --dimensions Name=RuleName,Value=aws-security-lab-guardduty-findings \
  --start-time "$(date -u -d '20 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 300 --statistics Sum
```

**Verified:** `Sum = 1.0`, confirming the rule matched and invoked its SNS
target.

**The severity filter is part of the test.** The default
`minimum_alert_severity = 4` means the LOW-severity
`Recon:EC2/PortProbeUnprotectedPort` sample should *not* trigger. If every
sample triggers, your filter is not working.

**Failure modes:**

- **`TriggeredRules` is zero** — the event pattern does not match. GuardDuty
  severity is numeric in the event (`4.0`), not a label, so a pattern
  filtering on `["MEDIUM"]` silently matches nothing.
- **`TriggeredRules` non-zero but no email** — the SNS subscription is
  unconfirmed. Terraform cannot confirm it for you; AWS emails a link.
  `aws sns list-subscriptions-by-topic --topic-arn <arn>` shows
  `PendingConfirmation`.
- **Rule fires, SNS publish fails** — almost always the KMS key policy. An
  SNS topic encrypted with the AWS-managed `alias/aws/sns` key **cannot** be
  published to by EventBridge, because that key's policy cannot be edited to
  trust `events.amazonaws.com`. This is why `30-detection` creates a CMK.

Note the deliberate asymmetry: the backup alerts topic in `60-data` *does*
use `alias/aws/sns`, because AWS Backup publishes via its own service
principal, which the managed key already trusts.

---

## Config auto-remediation

Requires `create_demo_bucket = true` in `stacks/40-autoremediate`.

```bash
terraform -chdir=stacks/40-autoremediate apply -var create_demo_bucket=true
./scripts/test-remediation.sh
```

### This test deliberately makes a bucket public

That is the only way to make `s3-bucket-public-read-prohibited` evaluate
`NON_COMPLIANT`. The script therefore:

- refuses to run against any bucket other than the throwaway fixture
- requires you to type `make it public`
- re-blocks the bucket on **every** exit path via a shell trap, including
  failure and interrupt

No Terraform in this repo ever creates a public bucket. The fixture is
created *without* a public access block — that absence is the test condition
— but it is not made public until you explicitly do it.

**What it proves:** the full loop. Rule detects → Config invokes the SSM
Automation document → document applies a public access block and asserts it
→ next evaluation returns `COMPLIANT`.

**Failure modes, in the order worth checking:**

1. **Account-level S3 Block Public Access is on.** It overrides bucket
   settings, so the bucket was never actually public and the rule correctly
   stayed `COMPLIANT`. This is the most common false failure.
   ```bash
   aws s3control get-public-access-block --account-id "$(aws sts get-caller-identity --query Account --output text)"
   ```
2. **Recorder not running.** Config rules cannot evaluate without it.
   ```bash
   aws configservice describe-configuration-recorder-status
   ```
3. **Remediation not automatic.**
   ```bash
   aws configservice describe-remediation-configurations \
     --config-rule-names s3-bucket-public-read-prohibited
   ```
4. **Automation ran and failed** — usually the assume role lacking
   `s3:PutBucketPublicAccessBlock`.
   ```bash
   aws ssm describe-automation-executions \
     --filters Key=DocumentNamePrefix,Values=security-lab-PutS3PublicAccessBlock
   ```

Config evaluation is not instant; allow a few minutes. The script polls for
five.

---

## Permission boundary

Proves the boundary actually subtracts, rather than just being attached.

```bash
ROLE=$(terraform -chdir=stacks/20-identity output -raw developer_role_arn)

# PowerUserAccess allows this; the boundary's DenyOutsideApprovedRegions
# should still deny it in a non-approved region.
aws iam simulate-principal-policy \
  --policy-source-arn "$ROLE" \
  --action-names ec2:RunInstances \
  --context-entries 'ContextKeyName=aws:RequestedRegion,ContextKeyType=string,ContextKeyValues=eu-west-1' \
  --query 'EvaluationResults[].EvalDecision' --output text

# And that it cannot mint an unconstrained principal.
aws iam simulate-principal-policy \
  --policy-source-arn "$ROLE" \
  --action-names iam:CreateRole \
  --query 'EvaluationResults[].EvalDecision' --output text
```

Both should report `implicitDeny` or `explicitDeny`. `simulate-principal-policy`
evaluates boundaries, so this is a real test rather than a reading of the
policy.

---

## Patch Manager

No instances exist in this lab, so there is nothing to patch. What you can
verify is that the baseline resolves its approved patch set:

```bash
aws ssm describe-effective-patches-for-patch-baseline \
  --baseline-id "$(terraform -chdir=stacks/80-vulnmgmt output -raw patch_baseline_id)" \
  --query 'length(EffectivePatches)'
```

A non-zero count proves the approval rules are syntactically valid *and*
match real patches. A baseline with mistyped filters returns zero while still
applying cleanly — which is how the lowercase `security` versus `Security`
bug would have gone unnoticed had the API not rejected it outright.

To test end to end, launch an instance with the
`aws-security-lab-ssm-managed-instance` instance profile and the tag
`Patch Group = aws-security-lab-linux`, then run the scan window manually.

---

## Order of operations

`40-autoremediate` turns on the Config recorder that most Security Hub
controls depend on. Testing Security Hub before applying it shows a
deceptively clean posture — controls sit at "No data" rather than failing.
Apply in numeric order, then test.
