#!/usr/bin/env bash
#
# One-time organization prerequisites that Terraform cannot express.
#
# Trusted access ("enable-aws-service-access") has no standalone
# Terraform resource. The only way to manage it in Terraform is to
# import `aws_organizations_organization`, which puts DeleteOrganization
# inside `terraform destroy` — a trade nobody should take. So it is a
# script, run once, idempotently.
#
# Must run in the ORGANIZATION MANAGEMENT ACCOUNT.
#
set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"

# --- Safety: confirm we are where we think we are ---------------------
CALLER_JSON="$(aws sts get-caller-identity --output json)"
ACCOUNT_ID="$(printf '%s' "$CALLER_JSON" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["Account"])')"

ORG_JSON="$(aws organizations describe-organization --output json)"
MGMT_ID="$(printf '%s' "$ORG_JSON" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["Organization"]["MasterAccountId"])')"
ORG_ID="$(printf '%s' "$ORG_JSON" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["Organization"]["Id"])')"

echo "account:      $ACCOUNT_ID"
echo "organization: $ORG_ID"
echo "management:   $MGMT_ID"
echo

if [ "$ACCOUNT_ID" != "$MGMT_ID" ]; then
  echo "ERROR: this is not the management account. Trusted access can only" >&2
  echo "       be enabled from $MGMT_ID." >&2
  exit 1
fi

# --- Trusted access ---------------------------------------------------
#
# Each principal lets the named service read organization structure and
# operate across member accounts. Enabling is idempotent; AWS returns
# success if it is already on.
SERVICES=(
  cloudtrail.amazonaws.com          # organization trail
  config.amazonaws.com              # organization config rules
  config-multiaccountsetup.amazonaws.com
  guardduty.amazonaws.com           # delegated admin + auto-enable
  securityhub.amazonaws.com         # delegated admin + central config
  access-analyzer.amazonaws.com     # organization analyzers
  inspector2.amazonaws.com          # delegated admin + auto-enable
  malware-protection.guardduty.amazonaws.com
  ram.amazonaws.com                 # resource sharing, needed by AFT
  sso.amazonaws.com                 # Identity Center
  backup.amazonaws.com              # organization backup policies
)

echo "Enabling trusted access:"
for svc in "${SERVICES[@]}"; do
  printf '  %-48s ' "$svc"
  if aws organizations enable-aws-service-access \
       --service-principal "$svc" 2>/dev/null; then
    echo "ok"
  else
    # Already enabled, or the service is unavailable in this partition.
    echo "already enabled or unavailable"
  fi
done

# --- Policy types -----------------------------------------------------
ROOT_ID="$(aws organizations list-roots \
  --query 'Roots[0].Id' --output text)"

echo
echo "Enabling policy types on root $ROOT_ID:"
for ptype in SERVICE_CONTROL_POLICY RESOURCE_CONTROL_POLICY TAG_POLICY; do
  printf '  %-28s ' "$ptype"
  if aws organizations enable-policy-type \
       --root-id "$ROOT_ID" --policy-type "$ptype" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "already enabled"
  fi
done

# --- Report what still needs a human ----------------------------------
echo
echo "----------------------------------------------------------------"
echo "Remaining manual step:"
echo
if aws sso-admin list-instances --region "$REGION" \
     --query 'Instances[0].InstanceArn' --output text 2>/dev/null \
     | grep -q 'arn:'; then
  echo "  Identity Center: already enabled."
else
  echo "  Identity Center is NOT enabled, and Terraform cannot enable it —"
  echo "  no resource exists, only the aws_ssoadmin_instances data source."
  echo
  echo "  Enable it once in the console:"
  echo "    https://console.aws.amazon.com/singlesignon/home?region=$REGION"
  echo
  echo "  Then set enable_identity_center = true in stacks/20-identity."
fi
echo "----------------------------------------------------------------"
