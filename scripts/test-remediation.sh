#!/usr/bin/env bash
#
# Proves the Config -> SSM Automation remediation loop from stack
# 40-autoremediate actually closes.
#
# ####################################################################
# THIS SCRIPT DELIBERATELY MAKES AN S3 BUCKET PUBLICLY READABLE.
#
# That is the only way to make the Config rule evaluate NON_COMPLIANT
# and the remediation fire. It therefore:
#   - refuses to run against any bucket it did not expect
#   - requires typed confirmation
#   - re-blocks the bucket itself if the remediation does not
#
# Terraform in this repo never creates a public bucket. The exposure
# exists only for the duration of this test, in a throwaway fixture.
# ####################################################################
#
set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
PROJECT="${PROJECT:-aws-security-lab}"
RULE_NAME="s3-bucket-public-read-prohibited"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${PROJECT}-remediation-demo-${ACCOUNT_ID}"

# --- Guard: only ever the expected fixture ----------------------------
if [[ "$BUCKET" != *"-remediation-demo-"* ]]; then
  echo "ERROR: refusing to operate on '$BUCKET'." >&2
  exit 1
fi

if ! aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo "ERROR: fixture bucket $BUCKET does not exist." >&2
  echo "       Apply stacks/40-autoremediate with create_demo_bucket = true." >&2
  exit 1
fi

# --- Guard: typed confirmation ----------------------------------------
cat <<EOF

About to make this bucket PUBLICLY READABLE for the duration of a test:

  bucket:  $BUCKET
  account: $ACCOUNT_ID
  region:  $REGION

The Config rule '$RULE_NAME' should then detect it and the SSM
Automation document should apply a public access block within a few
minutes. This script re-blocks the bucket itself if that does not
happen.

EOF

read -r -p "Type 'make it public' to continue: " CONFIRM
if [ "$CONFIRM" != "make it public" ]; then
  echo "Aborted."
  exit 1
fi

# --- Re-block on any exit path ----------------------------------------
cleanup() {
  echo
  echo "Ensuring the bucket is blocked before exit..."
  aws s3api put-public-access-block \
    --bucket "$BUCKET" \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --region "$REGION" 2>/dev/null || true
  aws s3api delete-bucket-policy --bucket "$BUCKET" --region "$REGION" 2>/dev/null || true
  echo "Bucket is blocked."
}
trap cleanup EXIT

# --- Step 1: create the violation -------------------------------------
echo
echo "[1/4] Removing the public access block..."
aws s3api delete-public-access-block --bucket "$BUCKET" --region "$REGION"

echo "[2/4] Attaching a public-read bucket policy..."
aws s3api put-bucket-policy --bucket "$BUCKET" --region "$REGION" --policy "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [{
    \"Sid\": \"TemporaryPublicReadForRemediationTest\",
    \"Effect\": \"Allow\",
    \"Principal\": \"*\",
    \"Action\": \"s3:GetObject\",
    \"Resource\": \"arn:aws:s3:::${BUCKET}/*\"
  }]
}"

echo "      Bucket is now public."

# --- Step 2: force an evaluation --------------------------------------
echo
echo "[3/4] Triggering Config evaluation..."
aws configservice start-config-rules-evaluation \
  --region "$REGION" \
  --config-rule-names "$RULE_NAME" 2>/dev/null \
  || echo "      (rule may already be evaluating)"

# --- Step 3: wait for the remediation --------------------------------
echo
echo "[4/4] Waiting up to 5 minutes for remediation..."
echo

REMEDIATED=0
for i in $(seq 1 30); do
  sleep 10

  COMPLIANCE="$(aws configservice get-compliance-details-by-config-rule \
    --region "$REGION" \
    --config-rule-name "$RULE_NAME" \
    --query "EvaluationResults[?EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId=='${BUCKET}'].ComplianceType | [0]" \
    --output text 2>/dev/null || echo "UNKNOWN")"

  PAB="$(aws s3api get-public-access-block \
    --bucket "$BUCKET" --region "$REGION" \
    --query 'PublicAccessBlockConfiguration.RestrictPublicBuckets' \
    --output text 2>/dev/null || echo "absent")"

  printf '  %3ds  compliance=%-14s public-access-block=%s\n' \
    "$((i * 10))" "$COMPLIANCE" "$PAB"

  if [ "$PAB" = "True" ]; then
    REMEDIATED=1
    break
  fi
done

echo
if [ "$REMEDIATED" -eq 1 ]; then
  cat <<EOF
PASS — the remediation fired and applied a public access block.

Inspect the automation run:
  aws ssm describe-automation-executions --region $REGION \\
    --filters Key=DocumentNamePrefix,Values=${PROJECT}-PutS3PublicAccessBlock
EOF
else
  cat <<EOF
No remediation observed within 5 minutes. Things to check, in order:

 1. Is the recorder running?
      aws configservice describe-configuration-recorder-status --region $REGION

 2. Is automatic remediation actually on?
      aws configservice describe-remediation-configurations --region $REGION \\
        --config-rule-names $RULE_NAME

 3. Did the automation run and fail?
      aws ssm describe-automation-executions --region $REGION \\
        --filters Key=DocumentNamePrefix,Values=${PROJECT}-PutS3PublicAccessBlock

 4. Account-level S3 Block Public Access overrides bucket settings. If it
    is on, the bucket was never really public and the rule correctly
    stayed COMPLIANT:
      aws s3control get-public-access-block --account-id $ACCOUNT_ID
EOF
fi

# trap re-blocks the bucket on the way out
