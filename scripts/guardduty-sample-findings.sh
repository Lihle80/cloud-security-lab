#!/usr/bin/env bash
#
# Generates GuardDuty sample findings to exercise the
# EventBridge -> SNS path from stack 30-detection.
#
# Sample findings are synthetic. They appear with "[SAMPLE]" in the
# title and are indistinguishable from real findings as far as
# EventBridge is concerned, which is exactly what makes them useful for
# testing a notification pipeline.
#
# Safe: creates no resources, touches nothing real, auto-archives.
#
set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"

DETECTOR_ID="$(aws guardduty list-detectors \
  --region "$REGION" \
  --query 'DetectorIds[0]' --output text)"

if [ "$DETECTOR_ID" = "None" ] || [ -z "$DETECTOR_ID" ]; then
  echo "ERROR: no GuardDuty detector in $REGION." >&2
  echo "       Apply stacks/30-detection first." >&2
  exit 1
fi

echo "detector: $DETECTOR_ID ($REGION)"
echo

# A spread across severities, so you can confirm the
# `minimum_alert_severity` filter in the EventBridge rule actually
# filters. With the default threshold of 4, the LOW finding below
# should NOT produce an email.
#
#   Recon:EC2/PortProbeUnprotectedPort        LOW     (~2.0) filtered out
#   UnauthorizedAccess:EC2/SSHBruteForce      MEDIUM  (~5.0) alerts
#   CryptoCurrency:EC2/BitcoinTool.B!DNS      HIGH    (~8.0) alerts
#   Backdoor:EC2/C&CActivity.B!DNS            HIGH    (~8.0) alerts
FINDING_TYPES=(
  "Recon:EC2/PortProbeUnprotectedPort"
  "UnauthorizedAccess:EC2/SSHBruteForce"
  "CryptoCurrency:EC2/BitcoinTool.B!DNS"
  "Backdoor:EC2/C&CActivity.B!DNS"
)

echo "Creating sample findings:"
for ft in "${FINDING_TYPES[@]}"; do
  printf '  %-45s ' "$ft"
  if aws guardduty create-sample-findings \
       --region "$REGION" \
       --detector-id "$DETECTOR_ID" \
       --finding-types "$ft" 2>/dev/null; then
    echo "ok"
  else
    echo "FAILED"
  fi
done

echo
echo "Findings are generated asynchronously; allow 30-60 seconds."
echo
# Note: filtering on service.additionalInfo.sample is rejected by the
# API (InvalidInputException) despite appearing in older examples. Plain
# list-findings plus a title check is what actually works — sample
# findings are prefixed "[SAMPLE]".
echo "Watch them arrive:"
echo "  aws guardduty list-findings --region $REGION --detector-id $DETECTOR_ID"
echo
echo "The authoritative check is the EventBridge metric below: it proves"
echo "the rule matched and invoked its SNS target. A non-zero Sum means"
echo "the detection path works end to end."
echo
echo "Confirm the EventBridge rule matched:"
echo "  aws cloudwatch get-metric-statistics --region $REGION \\"
echo "    --namespace AWS/Events --metric-name TriggeredRules \\"
echo "    --dimensions Name=RuleName,Value=aws-security-lab-guardduty-findings \\"
echo "    --start-time \"\$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)\" \\"
echo "    --end-time \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \\"
echo "    --period 300 --statistics Sum"
echo
echo "If TriggeredRules is non-zero but no email arrived, the SNS email"
echo "subscription is still unconfirmed — check your inbox."
