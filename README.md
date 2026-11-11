# AI GRC Gatekeeper

Proves: AI agent actions can be checked against written policy before they run, every decision lands in a tamper-evident log, and the build fails when a control, its mapping or its test goes missing.

Verify in 60s: `bash check.sh`

This repository is a mapping and a set of technical controls. It is not an attestation and not a legal opinion.

## The problem

Teams are letting AI agents call tools, send messages, spend money and deploy code. Policy documents say "a human approves production changes" and "no personal data leaves", but nothing in the pipeline checks it, and the log that would show what happened can be edited after the fact. A reviewer is left to trust a slide. This repo shows the smallest working version of the alternative: rules a machine can enforce, a human approval step that cannot be self-served or replayed, a log that shows tampering, and a CI check that keeps the paperwork and the code in step.

## What each module proves

| Module | What it proves | How you can see it |
|---|---|---|
| `src/policy_gate.py` | Seven written rules decide each action: deny, wait for a human, or allow. Deny beats wait, wait beats allow. Anything the gate cannot judge is denied. A bad rules file stops the run with exit 2. A requester cannot approve their own action, and an approval works for one action only. | `python3 src/policy_gate.py evaluate examples/actions.jsonl --ledger out/ledger.jsonl` |
| `src/audit_ledger.py` | Each log entry carries the hash of the one before it. An edit, delete, reorder or insert changes the chain and `verify` says where. | `python3 src/audit_ledger.py verify out/ledger.jsonl` |
| `src/ci_gate.py` | Every example action gets the decision its `expect` field states, the ledger verifies, every rule is mapped in `CONTROLS_MATRIX.md` to a test that exists, every rule has a `RISK_REGISTER.md` ticket, and every rule is exercised by at least one example. | `python3 src/ci_gate.py` |

## Real output

`bash check.sh` (tests, then mutation check, then CI gate):

```
== tests
.......................................................
----------------------------------------------------------------------
Ran 55 tests in 0.851s

OK
== mutants
baseline: unmutated copy passes
  killed   deny downgraded to allow
  killed   prev_hash left out of the entry hash
  killed   separation of duties removed
  killed   unknown-field fail-closed removed
  killed   ci_gate always exits 0
  killed   regex operator disabled
  killed   approver list check removed
  killed   approval replay binding removed
  killed   ledger sequence check removed
  killed   ledger prev_hash link check removed
  killed   ledger hash recompute removed
  killed   malformed rules exit code changed to 0
  killed   controls matrix check skipped
  killed   spend limit off by one (gt becomes gte)
  killed   negate flag ignored
  killed   head anchor check removed
  killed   ledger append forgets the previous hash
  killed   unexercised-rule check removed
  killed   missing-field fail-closed removed
mutants 19/19 killed
== ci gate
CI GATE: decisions match expect: 15/15
CI GATE: ledger chain intact, head matches the hash written this run: yes
CI GATE: rules mapped in CONTROLS_MATRIX.md with an existing test: 7/7
CI GATE: rules with a RISK_REGISTER ticket: 7/7
CI GATE: GREEN
CHECK: GREEN
```

The policy gate on the synthetic actions in `examples/actions.jsonl`:

```
ALLOW    a-001    -
DENY     a-002    R-TOOL-003
ALLOW    a-003    -
DENY     a-004    R-PII-001
DENY     a-005    R-PII-001
ALLOW    a-006    -
PENDING  a-007    R-SPEND-002 approval=APR-0001-bebea164
ALLOW    a-008    -
PENDING  a-009    R-DEPLOY-004 approval=APR-0002-45eb0a6e
PENDING  a-010    R-EXTSEND-005 approval=APR-0003-248bfef0
ALLOW    a-011    -
DENY     a-012    R-RAG-006
DENY     a-013    R-LABEL-007
DENY     a-014    FAIL-CLOSED
DENY     a-015    R-EXTSEND-005,R-PII-001
SUMMARY total=15 allow=5 deny=7 pending=3
```

Verifying the ledger, then changing one byte in a copy and verifying again:

```
$ python3 src/audit_ledger.py verify out/ledger.jsonl
LEDGER OK: chain intact          (exit 0)

$ python3 src/audit_ledger.py verify out/ledger_copy.jsonl
LEDGER TAMPERED at seq 3: hash mismatch: entry content was changed          (exit 1)
```

## How an auditor reproduces it

1. Clone the repository. You need `python3` (3.9 or newer) and `bash`. Nothing is installed.
2. Run `bash check.sh`. It ends with `CHECK: GREEN` and exit code 0, or `CHECK: RED` and exit code 1.
3. Read `policies/rules.yaml`. Each rule has an id, a severity, a match and an effect. Change one, for example lower the spend limit from 500 to 100, and run `bash check.sh` again to see the tests and the CI gate notice.
4. Run the policy gate command above, then `python3 src/audit_ledger.py verify out/ledger.jsonl`. Copy the ledger, edit one character in the copy, verify the copy. It exits 1 and names the entry.
5. Open `CONTROLS_MATRIX.md`. Pick a row, open the named test in `tests/test_compliance.py`, and confirm it checks what the row says.
6. Optional: with `pytest` installed, `python3 -m pytest -q -p no:cacheprovider` runs the same tests.

`policies/rules.yaml` is written as JSON on purpose. JSON is a subset of YAML 1.2, so any YAML tool reads it and the Python standard library parses it with no extra package. JSON has no comments, so field meanings are documented here and in `CONTROLS_MATRIX.md`.

To make the check block merges, set the `compliance-gate` job in `.github/workflows/grc_gate.yml` as a required status check on the deploy branch in repository settings; a failing gate then blocks merge to that branch.

## Honesty statement

- Every count in this repository comes from running the code. `bash check.sh` reproduces the test count, the mutant count and the 15/15, 7/7 and 7/7 results shown above.
- The mutation check proves the tests have teeth. It breaks the code on purpose in 19 named ways, such as turning a deny into an allow or removing the separation-of-duties check, and each break must make a test fail. While building it, two ledger checks survived because other checks covered for them; I added two tests that isolate them, and all 19 are now killed.
- A gap is reported, never passed. Empty input, an unmapped rule, a rule no example exercises, a malformed rules file or a damaged ledger turns the result RED instead of quietly passing.

## Limitations

- Integrity, not authenticity. The ledger shows that history changed. It has no signature, so it does not show who wrote an entry. Entries removed from the end are caught only if you recorded the head hash somewhere the writer cannot edit (`verify FILE --head HASH`). Someone who can rewrite the whole file and your record of the head can rewrite history.
- Synthetic actions. The 15 examples are invented to exercise each rule. They are not production traffic, and the pattern rules (email, SSN shape, confidentiality words) catch common shapes only.
- Approver identity is a plain string in this reference, and approvals are held in memory for the life of the process. A real deployment needs authenticated identities and a persistent approval store.
- Actions of a known type that match no rule are allowed. The rules are a deny list plus two allowlists, not a default-deny policy.
- The mapping to NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689 is the author's judgment, for an assessor to accept or change. Confirm clause text against the published standard.
- This is not a legal opinion and does not tell you whether any law applies to your system.

## Layout

| Path | Purpose |
|---|---|
| `policies/rules.yaml` | The seven rules, approver list, known fields (JSON) |
| `src/policy_gate.py` | Rule evaluation, fail-closed behaviour, human approval |
| `src/audit_ledger.py` | Append-only hash-chained log and `verify` |
| `src/ci_gate.py` | The CI check over decisions, ledger, mapping and tickets |
| `tests/test_compliance.py` | The unit tests |
| `tests/mutants.py` | Mutation check |
| `examples/actions.jsonl` | Synthetic agent actions, each with an `expect` field |
| `CONTROLS_MATRIX.md` | Rule to framework references, evidence and test |
| `RISK_REGISTER.md` | Tickets for the risks the rules address |
| `INCIDENT_RUNBOOK.md` | What to do when the gate fires |
| `SYSTEM_CARD.md` | One page for a VP or lawyer |
| `check.sh` | One command, one verdict |
| `.github/workflows/` | `ci.yml` runs `check.sh`; `grc_gate.yml` runs the CI gate on pull requests |
