# Cross-account KMS

Part of lab item 6. The thing to understand: **cross-account KMS needs grants
on both sides, and listing an ARN in the key policy is only one of them.**

Configured in this lab between:

| Role | Account |
|---|---|
| Key owner | `<OWNER-ACCOUNT-ID>` (management) |
| Key consumer | `<CONSUMER-ACCOUNT-ID>` ("Sanbox") |

---

## Why one grant is never enough

AWS evaluates cross-account KMS access as **two independent authorisation
decisions**, and both must allow:

```
                  Account A (key owner)        Account B (consumer)
                  ---------------------        --------------------
  1. Key policy   grants B's principal   ✓
  2. IAM policy                                grants kms:Decrypt on
                                               A's key ARN            ✓
                                               -------------------------
                                               both required
```

This is unlike same-account access, where a permissive key policy
(`EnableIAMPolicies`, delegating to IAM) is sufficient. Cross-account, the key
policy **cannot** delegate to the other account's IAM — it must name the
principal explicitly.

The usual failure: you add the ARN to the key policy, see no error from
Terraform, and then get `AccessDeniedException` at runtime because nobody
configured side 2. Terraform cannot warn you, because side 2 lives in an
account it is not managing.

---

## Side 1 — the key policy (this repo)

`stacks/60-data/kms.tf`:

```hcl
dynamic "statement" {
  for_each = local.has_cross_account ? [1] : []

  content {
    sid       = "CrossAccountDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = var.cross_account_principal_arns
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}
```

Set via `stacks/60-data/terraform.tfvars`:

```hcl
cross_account_principal_arns = ["arn:aws:iam::<CONSUMER-ACCOUNT-ID>:root"]
```

Three things to notice.

**`Resource: "*"` is correct and mandatory.** In a key policy that string means
"this key, the one the policy is attached to". An ARN there is rejected by the
API. Checkov flags it as three separate findings (`CKV_AWS_111`, `356`, `109`)
which can never pass on a valid key policy — suppressed with that reasoning in
`.checkov.yaml`.

**`:root` means "any principal in that account", not the root user.** It
delegates the decision to account B's IAM, which is exactly why side 2 is
required. To be stricter, name the role directly:

```hcl
cross_account_principal_arns = [
  "arn:aws:iam::<CONSUMER-ACCOUNT-ID>:role/data-reader"
]
```

That role must exist before you apply, or KMS rejects the policy with
`MalformedPolicyDocumentException: Policy contains a statement with one or
more invalid principals`. KMS validates principals at write time — unlike IAM
policies, which accept ARNs for things that do not exist yet.

**`kms:ViaService` is the control that makes this safe.** Without it, account B
can call `Decrypt` directly on arbitrary ciphertext and the key becomes a
general-purpose decryption oracle. With it, B can only decrypt data arriving
through S3 in this region.

**Only `Decrypt` and `DescribeKey` are granted.** Not `Encrypt`, not
`GenerateDataKey`. Account B can read what you share; it cannot write objects
you are then obliged to store and cannot read.

---

## Side 1b — the bucket policy

A KMS grant alone gets you a decryptable blob you cannot fetch. The object
grant is separate, in `stacks/60-data/s3_bucket_policy.tf`:

```hcl
dynamic "statement" {
  for_each = local.has_cross_account ? [1] : []

  content {
    sid       = "CrossAccountRead"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]

    resources = [
      aws_s3_bucket.protected.arn,
      "${aws_s3_bucket.protected.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = var.cross_account_principal_arns
    }
  }
}
```

Note the two distinct resources: `ListBucket` acts on the **bucket** ARN,
`GetObject` on the **object** ARN with `/*`. Granting only the `/*` form
produces a confusing failure where individual gets succeed but listing returns
`AccessDenied`.

---

## Side 2 — in the consumer account

**Not in this repo**, because this repo manages account A. Apply this in
account `<CONSUMER-ACCOUNT-ID>`:

```hcl
data "aws_iam_policy_document" "read_shared_data" {
  statement {
    sid    = "ReadSharedBucket"
    effect = "Allow"

    actions = ["s3:GetObject", "s3:ListBucket"]

    resources = [
      "arn:aws:s3:::aws-security-lab-protected-<OWNER-ACCOUNT-ID>",
      "arn:aws:s3:::aws-security-lab-protected-<OWNER-ACCOUNT-ID>/*",
    ]
  }

  statement {
    sid    = "DecryptSharedData"
    effect = "Allow"

    actions = ["kms:Decrypt", "kms:DescribeKey"]

    # The key ARN in the OWNER's account. An alias will not work —
    # aliases are account-local and do not resolve cross-account.
    resources = [
      "arn:aws:kms:us-west-2:<OWNER-ACCOUNT-ID>:key/<KEY-ID>"
    ]
  }
}
```

**The alias trap:** `alias/aws-security-lab-data` resolves only inside account
A. From account B you must use the full key ARN. This produces a
`NotFoundException` that reads as though the key does not exist.

---

## Verifying

From account B, with credentials for the granted principal:

```bash
# Does the key policy allow me?
aws kms describe-key \
  --key-id arn:aws:kms:us-west-2:<OWNER-ACCOUNT-ID>:key/<KEY-ID>

# Can I list?
aws s3 ls s3://aws-security-lab-protected-<OWNER-ACCOUNT-ID>/

# The real test — needs BOTH grants plus the KMS decrypt
aws s3 cp s3://aws-security-lab-protected-<OWNER-ACCOUNT-ID>/<key> -
```

Reading the error tells you which side is missing:

| Error | Missing |
|---|---|
| `AccessDenied` on `ListBucket` | bucket policy, or side 2's S3 statement |
| `AccessDenied` on `GetObject`, listing works | bucket policy `/*` resource |
| `KMS.AccessDeniedException` on download | key policy, or side 2's KMS statement |
| `NotFoundException` on the key | using an alias instead of the full ARN |
| Decrypt denied despite both policies | `kms:ViaService` excludes how you called it |

From the owner account, confirm who the key trusts:

```bash
aws kms get-key-policy \
  --key-id alias/aws-security-lab-data \
  --policy-name default --output text | python3 -m json.tool
```

And check Access Analyzer, which exists precisely to surface this:

```bash
aws accessanalyzer list-findings \
  --analyzer-arn "$(terraform -chdir=stacks/10-org output -raw external_access_analyzer_arn)" \
  --query 'findings[?resourceType==`AWS::KMS::Key`]'
```

The organization analyzer from `stacks/10-org` reports resource policies
granting access outside the org. A grant to `<CONSUMER-ACCOUNT-ID>` is **inside** this
organization, so it correctly produces no finding — if it did show up, the ARN
would be wrong.

---

## What this does not cover

**Bucket owner vs object owner.** If account B ever *writes* to the bucket,
objects it creates are owned by B and account A cannot read them by default.
`60-data` sets `object_ownership = "BucketOwnerEnforced"`, which disables ACLs
entirely and makes A the owner of everything — the right setting, and the
reason the grant above is read-only.

**Encrypting from account B.** Would need `kms:GenerateDataKey` added to the
key policy, plus `s3:PutObject`. Deliberately not granted; a read-only
consumer is the safer default.

**Key rotation.** Automatic rotation keeps the same key ID and ARN, so nothing
on side 2 changes. Old key material is retained to decrypt older data. Manual
rotation to a *new* key would break side 2 and require updating the ARN there.
