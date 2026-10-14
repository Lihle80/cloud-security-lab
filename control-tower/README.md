# Control Tower and Account Factory for Terraform — lab item 1

> **Status: written, reviewed, NOT APPLIED.**
>
> Everything else in this repo was applied to a real account. This directory
> was not, for the reasons below. That is a deliberate decision, not an
> unfinished corner.

## Why this is the one stack that stays unapplied

**It requires creating two real AWS accounts.** A Control Tower landing zone
cannot create its own Log Archive and Audit accounts — you pass it the IDs of
accounts that already exist. So deploying this means calling
`organizations:CreateAccount` twice.

In the lab organization that is a problem:

- The organization is Isengard-managed. Accounts created through the
  Organizations API are **not** Isengard-managed, so they fall outside the
  normal ownership and lifecycle tooling while still billing to Amazon.
- Closing an AWS account is a **90-day** process. There is no fast undo. Get
  the email addresses wrong and you own two orphans for a quarter.
- Control Tower enrolls every account in the governed OUs and deploys
  StackSets into them. Decommissioning a landing zone is a multi-step
  operation that frequently leaves StackSet instances behind.
- Landing zone setup takes 60–90 minutes, and a failure partway through
  leaves the organization in a state Terraform cannot reconcile.

The guardrails this lab actually needed — OU structure, SCPs, org-wide
CloudTrail, delegated-admin GuardDuty and Security Hub — are all in
`stacks/10-org` and `stacks/30-detection`, applied and working. Control Tower
would package them differently; it would not add a control that is missing.

## What to change before applying this

1. Create the two accounts and record their IDs:

   ```bash
   aws organizations create-account \
     --email you+log-archive@example.com \
     --account-name "Log Archive"

   aws organizations create-account \
     --email you+audit@example.com \
     --account-name "Audit"
   ```

   Each email must be globally unique across all of AWS and must be one you
   can actually receive mail at — root password recovery depends on it.

2. Set `log_archive_account_id` and `audit_account_id` in
   `landing-zone/terraform.tfvars`.

3. Confirm no landing zone already exists:

   ```bash
   aws controltower list-landing-zones --region us-west-2
   ```

4. Apply from `landing-zone/`, then `aft/`.

## Proactive controls are CloudFormation Hooks

The part of Control Tower that connects most directly to IaC work.

Control Tower controls come in three flavours, and the distinction matters:

| Flavour | Mechanism | When it acts |
|---|---|---|
| **Preventive** | SCP | blocks the API call outright |
| **Detective** | Config rule | reports after the fact |
| **Proactive** | **CloudFormation Hook** | blocks at deploy time, before creation |

Proactive controls run as `AWS::CloudFormation::Hook` resources invoked during
`CREATE`/`UPDATE` on a CloudFormation stack. They evaluate the *intended*
resource properties and fail the stack operation before anything is
provisioned.

The practical consequence: **a proactive control does not see Terraform.**
Terraform calls service APIs directly, so a Hook never fires. An
SCP-backed preventive control does apply to Terraform, because it is enforced
at the API layer.

So in a Terraform shop, proactive controls cover only the CloudFormation path
— Service Catalog products, AFT's own StackSets, CDK deployments — and the
preventive SCPs in `stacks/10-org` are what govern Terraform-provisioned
infrastructure. The `cfn-guard` job in the CI pipeline is the closest
Terraform-side equivalent: same policy-as-code idea, enforced in the pipeline
rather than by the control plane.

## AFT, and whether it is worth it

Account Factory for Terraform gives you a GitOps account vending pipeline:
commit a request to a repo, AFT provisions and customises the account.

It is genuinely heavy. AFT deploys into a **dedicated fifth account** and
stands up CodePipeline, CodeBuild, Step Functions, DynamoDB, SQS, Lambda and
four separate Git repositories. The running cost is real and mostly fixed
regardless of how many accounts you vend.

Worth it above roughly 10–15 accounts, or when account customisation must be
reviewable and version-controlled. Below that, `aws controltower
create-managed-account` plus the Terraform in `stacks/` is less machinery for
the same outcome.

`aft/main.tf` carries the full module invocation with every prerequisite
documented, so the shape is clear without paying to run it.
