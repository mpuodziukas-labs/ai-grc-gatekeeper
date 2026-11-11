# Incident runbook: when the gate fires

A standard operating procedure for the gate in this repository. Role names are placeholders; replace them with your own. Time targets are targets the organization chooses to hold itself to. They are not claims about past performance. This document is a procedure, not a legal opinion.

## 1. Severity

| Level | Meaning | Examples | Acknowledge within (target) |
|---|---|---|---|
| SEV1 | Harm may already have happened, or the evidence itself is in doubt | The ledger fails `verify`; an action ran that the gate would have denied; personal data confirmed to have left the organization | 15 minutes |
| SEV2 | The gate stopped something, but the pattern suggests misuse or a broken agent | Repeated DENY lines from one agent in a short window; a `REPLAY_REFUSED` or a self-approval attempt; a FAIL-CLOSED line for a field the agent should never send | 1 hour |
| SEV3 | Expected block with a clear cause | One DENY for a tool not yet on the allowlist; one PENDING waiting for a normal approval | 1 business day |

## 2. Detect

Signals, in order of how often you will see them:

- A gate line that starts with `DENY` or `PENDING` (for example `DENY a-012 R-RAG-006`).
- A ledger entry with the same decision and rule id.
- `bash check.sh` or the `compliance-gate` job turning RED in CI.
- `python3 src/audit_ledger.py verify FILE` exiting 1 (tampered) or 2 (unreadable or malformed).

## 3. Contain

- A DENY already contains the action: it did not run. Do not retry it.
- A PENDING action stays on hold until a listed approver who is not the requester approves it.
- If an agent keeps triggering SEV2 signals, quarantine it: remove its credentials or its entry on the tool allowlist (`policies/rules.yaml`) and record the change in the corrective action log below.
- If the ledger fails verify, copy the file and its latest backup to read-only storage before anyone touches it. Work from the copy.

## 4. Triage

Run these from the repository root, against the ledger the gate wrote (the default is `out/ledger.jsonl`).

| Question | Command |
|---|---|
| Is the log intact? | `python3 src/audit_ledger.py verify out/ledger.jsonl` |
| Is it intact against the head hash we recorded? | `python3 src/audit_ledger.py verify out/ledger.jsonl --head <recorded hash>` |
| Every entry for one rule | `grep -F '"R-PII-001"' out/ledger.jsonl` |
| Every denial | `grep -F '"decision":"DENY"' out/ledger.jsonl` |
| Everything one agent did | `grep -F '"actor":"agent-support"' out/ledger.jsonl` |
| Approval trouble | `grep -e APPROVAL_REFUSED -e REPLAY_REFUSED out/ledger.jsonl` |
| Fail-closed events | `grep -F '"FAIL-CLOSED"' out/ledger.jsonl` |

Then answer, and write the answers in the corrective action log:

1. Which rule fired, and was it right? A false positive is a rule problem. A true positive is an agent or process problem.
2. Which agent, which action, and what was it trying to do? The `action` field holds the type, id and the sha256 of the action.
3. Did anything get past the gate? Compare the action list with what the downstream system actually did.
4. Is the ledger intact? If not, treat as SEV1.

## 5. Escalate

| Severity | Notify | Target |
|---|---|---|
| SEV1 | Head of Security Engineering, Privacy Officer, Legal Ops lead, risk owner of the matching ticket in `RISK_REGISTER.md` | 15 minutes |
| SEV2 | Risk owner of the matching ticket, Head of Platform Engineering | 1 hour |
| SEV3 | Ticket owner, by normal queue | 1 business day |

## 6. Root cause and corrective action

Record each incident as a row. This is the nonconformity and corrective action record (ISO/IEC 42001:2023 clause 10.2 in the author's mapping).

| Date | Incident | Rule or control | Root cause | Corrective action | Owner role | Verified by (test or mutant name) | Closed |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

A corrective action is not closed until the "verified by" column names a test that fails without the fix.

## 7. Serious-incident reporting

EU AI Act Article 73 (reporting of serious incidents) applies to providers of high-risk AI systems. Whether this system, this deployment or this event falls under it is a legal question. Legal decides; do not decide it from this document. Hand Legal the triage answers from section 4 and the ledger copy. Also consider obligations that apply to your organization outside the EU AI Act, such as breach notification for personal data, which Legal and the Privacy Officer decide.

## 8. After the incident

Every incident leaves three things behind:

1. A rule change in `policies/rules.yaml`, or a written reason no rule change is needed.
2. A test in `tests/test_compliance.py` that fails without the change.
3. A mutant in `tests/mutants.py` that breaks the new behaviour, so the test is proven to have teeth.

Then add or update the row in `CONTROLS_MATRIX.md` and the ticket in `RISK_REGISTER.md`. `bash check.sh` will not go GREEN until the rule, mapping, ticket and test agree.
