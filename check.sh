#!/usr/bin/env bash
# One command, one verdict: unit tests, mutation check, then the CI gate.
# Any failing step makes the whole run RED and the exit code 1.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1
status=0

step() {
  local label="$1"; shift
  echo "== $label"
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "$out" | tail -n "${TAIL:-6}"
  if [ "$rc" -ne 0 ]; then echo "STEP FAILED: $label (exit $rc)"; status=1; fi
}

step "tests" "$PY" -m unittest discover -s tests
TAIL=30 step "mutants" "$PY" tests/mutants.py
TAIL=8 step "ci gate" "$PY" src/ci_gate.py

if [ "$status" -eq 0 ]; then
  echo "CHECK: GREEN"
else
  echo "CHECK: RED"
fi
exit "$status"
