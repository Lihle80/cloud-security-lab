# Secrets and parameters

Lab item 7. Three ways to hold a credential on AWS, when each is right, and
the one thing that disqualifies Terraform from authoring secret values at all.

---

## The state problem

Start here, because it decides the rest.

**Any value Terraform manages is written to state in plaintext.** State
encryption at rest does not change this — anyone who can read the state file
can read the value. So:

```hcl
# WRONG. The password is now in terraform.tfstate, in your shell history,
# and in the plan output posted to the PR.
resource "aws_db_instance" "bad" {
  username = "admin"
  password = var.db_password
}
```

There is no clever variable handling that fixes this. The only real fix is for
Terraform never to see the value.

Compare `stacks/70-secrets/rds_rotation.tf`, which has **no `password`
argument at all**:

```hcl
resource "aws_db_instance" "this" {
  username = "labadmin"

  manage_master_user_password   = true
  master_user_secret_kms_key_id = data.aws_kms_key.data[0].arn
}
```

RDS generates the password, stores it in Secrets Manager, and owns rotation.
Terraform only ever learns the secret's **ARN**, which is safe to output. That
asymmetry — ARN in state, value never — is the pattern worth internalising.

---

## Option 1: RDS-managed master passwords

What this lab uses. `manage_master_user_password = true`.

**Why it is the right default for RDS:**

- The password never exists outside AWS. Not in state, not in a variable, not
  in CI logs.
- AWS owns the rotation Lambda. Nothing to write, deploy, patch, or hold IAM
  for.
- Rotation is coordinated with the engine as a single step, so there is no
  window where the stored secret and the actual password disagree.
- Rotation schedule is still yours:

  ```hcl
  resource "aws_secretsmanager_secret_rotation" "db_master" {
    secret_id          = aws_db_instance.this[0].master_user_secret[0].secret_arn
    rotate_immediately = false

    rotation_rules {
      automatically_after_days = var.rotation_days
    }
  }
  ```

  `rotate_immediately = false` matters: rotating during the apply races the
  instance becoming available.

**Limits:** only the *master* user, and only RDS/Aurora. Application users
within the database are not covered.

### How an application consumes it

Never copy the credential. Fetch it at startup, and on auth failure:

```python
import boto3, json

sm = boto3.client("secretsmanager")
ssm = boto3.client("ssm")

arn = ssm.get_parameter(Name="/security-lab/app/db-secret-arn")["Parameter"]["Value"]
creds = json.loads(sm.get_secret_value(SecretId=arn)["SecretString"])
# {"username": "labadmin", "password": "..."}
```

The indirection through Parameter Store means rotation is invisible to the
application — it always fetches the current value. An app that caches the
password forever will break on the first rotation, which is the usual reason
teams disable rotation rather than fix the client.

**Better still, skip the password.** The instance sets
`iam_database_authentication_enabled = true`, so a role can generate a
15-minute token instead:

```bash
aws rds generate-db-auth-token \
  --hostname "$ENDPOINT" --port 5432 --username labadmin
```

Nothing to rotate, nothing to leak.

---

## Option 2: Customer-managed secret with a rotation Lambda

Not used here. Worth knowing when you would need it.

**Reach for it when:**

- The target is not RDS — a third-party API key, an on-premises database, a
  service account in another SaaS.
- You need **multi-user** rotation, where two credentials alternate so there is
  zero downtime during the swap.
- The secret has a custom shape that AWS's templates do not produce.
- You need rotation of a *non-master* database user.

**What it costs you:** a Lambda in a VPC with the right security groups and
either NAT or interface endpoints, plus an IAM role, plus the four-step
rotation contract.

That contract is the part people get wrong. The function is invoked four times
per rotation with a `Step` value:

| Step | Responsibility |
|---|---|
| `createSecret` | Generate the new value, store as `AWSPENDING` |
| `setSecret` | Apply it to the target service |
| `testSecret` | **Verify it actually works** |
| `finishSecret` | Promote `AWSPENDING` to `AWSCURRENT` |

Skipping or stubbing `testSecret` is the classic bug: `finishSecret` promotes a
credential that was never validated, and the application loses access at the
moment of rotation rather than at the moment of the mistake.

Start from AWS's published templates in the
`SecretsManagerRDSPostgreSQLRotationSingleUser` SAR application rather than
writing the state machine from scratch.

---

## Option 3: Parameter Store

For things that are not rotating credentials.

```hcl
resource "aws_ssm_parameter" "api_key" {
  name   = "${local.parameter_prefix}/app/api-key"
  type   = "SecureString"          # this is what engages KMS
  key_id = data.aws_kms_key.data_for_params.arn
  value  = "PLACEHOLDER-SET-OUT-OF-BAND"

  lifecycle {
    ignore_changes = [value]       # see "the state problem"
  }
}
```

The `ignore_changes` plus placeholder is the honest workaround: Terraform
creates the parameter and never learns the real value, which is written once
out of band:

```bash
aws ssm put-parameter \
  --name /security-lab/app/api-key \
  --value "$REAL_VALUE" \
  --type SecureString \
  --key-id alias/aws-security-lab-data \
  --overwrite
```

Without `ignore_changes`, every subsequent plan would try to reset the real
value back to `PLACEHOLDER`.

### `String` vs `SecureString`

`stacks/70-secrets` deliberately creates both, and that contrast is the lesson:

```hcl
# Not a secret. A hostname. Encrypting it achieves nothing except making
# it harder to read and adding KMS calls to every fetch.
resource "aws_ssm_parameter" "db_endpoint" {
  type  = "String"
  value = aws_db_instance.this[0].address
}
```

Checkov flags this as `CKV2_AWS_34` ("should be encrypted"). The finding is
wrong here, and the suppression in `.checkov.yaml` says why. A secret ARN and
a database hostname are not secrets — they are useless without credentials,
and treating everything as secret is how teams end up with KMS bills and no
clearer security posture.

### Reserved prefix

Parameter names may not begin with `aws` or `ssm`, case-insensitive:

```
AccessDeniedException: No access to reserved parameter name:
aws-security-lab/app/db-endpoint
```

Hence `local.parameter_prefix = "/${replace(var.project, "/^aws-/", "")}"`.
The same constraint bites SSM document names and patch baseline names — see
[RUNBOOK.md](RUNBOOK.md#reserved-name-prefixes).

---

## Choosing

| | Secrets Manager | Parameter Store |
|---|---|---|
| Price | ~$0.40/secret/month + $0.05/10k calls | free (Standard), $0.05/10k (Advanced) |
| Max size | 64 KB | 4 KB Standard, 8 KB Advanced |
| Rotation | built in, managed for RDS | none — you build it |
| Cross-region | native replication | manual |
| Resource policy | yes | no |
| Versioning | staged labels (`AWSCURRENT`/`AWSPENDING`) | integer versions |
| Generates values | yes (`GetRandomPassword`) | no |
| Encryption | always | only with `SecureString` |

**Rule of thumb:** if it must rotate, Secrets Manager. If it merely must not be
public — endpoints, feature flags, non-rotating config — Parameter Store, where
it is free.

The resource-policy row is the one that decides borderline cases. Parameter
Store has no resource policy, so cross-account sharing is impossible without a
proxy role. If another account needs the value, that forces Secrets Manager
regardless of cost.

---

## Access control

The reader role in `parameter_store.tf` is scoped two ways, and the second is
the one people omit:

```hcl
statement {
  sid       = "DecryptSecureStrings"
  actions   = ["kms:Decrypt"]
  resources = [data.aws_kms_key.data_for_params.arn]

  condition {
    test     = "StringEquals"
    variable = "kms:ViaService"
    values   = ["ssm.${var.region}.amazonaws.com"]
  }
}
```

`kms:ViaService` means the role can decrypt **only** through Parameter Store.
Without it, granting `kms:Decrypt` on the key hands over the ability to
decrypt anything else that key protects — including, in this lab, the
`protected` S3 bucket, since `60-data` uses one key for both.

Separate keys per data class would be the stronger design. One key with
`ViaService` conditions is the pragmatic middle ground, and the condition is
what makes it defensible.
