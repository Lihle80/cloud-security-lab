#!/usr/bin/env bash
#
# Runs locally exactly what the PR pipeline runs, so you find problems
# before pushing. Needs no AWS credentials.
#
#   terraform fmt       formatting
#   terraform validate  syntax and type checking, per stack
#   checkov             broad policy scan
#   tfsec               Terraform-native scan
#   cfn-guard           SSM Automation documents
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAILED=0
step() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
ok()   { printf '\033[32mOK\033[0m   %s\n' "$1"; }

# --- fmt --------------------------------------------------------------
step "terraform fmt"
if terraform fmt -check -recursive -diff; then
  ok "all files formatted"
else
  fail "run: terraform fmt -recursive"
fi

# --- validate ---------------------------------------------------------
#
# control-tower/aft is excluded by default: `init` there downloads the
# AFT registry module and its whole dependency tree, which takes several
# minutes. Set VALIDATE_AFT=1 to include it.
step "terraform validate"
while IFS= read -r dir; do
  if [ "$dir" = "control-tower/aft" ] && [ "${VALIDATE_AFT:-0}" != "1" ]; then
    echo "SKIP $dir (set VALIDATE_AFT=1 to include; downloads a large module)"
    continue
  fi

  if terraform -chdir="$dir" init -backend=false -input=false >/dev/null 2>&1 \
     && terraform -chdir="$dir" validate >/dev/null 2>&1; then
    ok "$dir"
  else
    fail "$dir"
    terraform -chdir="$dir" validate 2>&1 | sed 's/^/       /' | head -20
  fi
done < <(find stacks control-tower -name '*.tf' -printf '%h\n' 2>/dev/null | sort -u)

# --- checkov ----------------------------------------------------------
step "checkov"
if command -v checkov >/dev/null 2>&1; then
  if checkov -d . --framework terraform --config-file .checkov.yaml \
       --compact --quiet; then
    ok "no findings outside documented skips"
  else
    fail "checkov reported findings"
  fi
else
  echo "SKIP checkov not installed (pip install checkov)"
fi

# --- tfsec ------------------------------------------------------------
step "tfsec"
if command -v tfsec >/dev/null 2>&1; then
  if tfsec . --no-color; then
    ok "no findings outside documented ignores"
  else
    fail "tfsec reported findings"
  fi
else
  echo "SKIP tfsec not installed"
fi

# --- cfn-guard --------------------------------------------------------
step "cfn-guard"
if command -v cfn-guard >/dev/null 2>&1; then
  shopt -s nullglob
  docs=(stacks/*/documents/*.yaml)
  if [ ${#docs[@]} -eq 0 ]; then
    echo "SKIP no documents found"
  else
    for d in "${docs[@]}"; do
      if cfn-guard validate --rules policies/ssm-document.guard \
           --data "$d" --show-summary fail >/dev/null 2>&1; then
        ok "$d"
      else
        fail "$d"
        cfn-guard validate --rules policies/ssm-document.guard \
          --data "$d" --show-summary fail 2>&1 | sed 's/^/       /' | head -20
      fi
    done
  fi
else
  echo "SKIP cfn-guard not installed"
fi

# --- result -----------------------------------------------------------
echo
if [ "$FAILED" -eq 0 ]; then
  printf '\033[32mAll checks passed.\033[0m\n'
else
  printf '\033[31mOne or more checks failed.\033[0m\n'
fi
exit "$FAILED"
