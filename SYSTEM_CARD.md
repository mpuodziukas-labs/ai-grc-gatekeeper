# System card: AI GRC Gatekeeper

This is a mapping and a set of technical controls. It is not an attestation and not a legal opinion.

## What it does

It sits between an AI agent and the things the agent wants to do (call a tool, send a message, spend money, deploy code, load a data source). For each requested action it returns one of three answers, writes the answer to a tamper-evident log, and, in CI, fails the build if the controls, their documentation or their tests drift apart.

## Who it is for

A CISO, Head of Risk or Legal Ops who needs to see that written policy is enforced by something other than good intentions. It is a reference implementation of the pattern, small enough to read in one sitting. It is not a product.

## What it blocks

| Rule | Situation | Answer |
|---|---|---|
| R-PII-001 | Outbound text contains an email address or a US SSN-shaped number | Deny |
| R-LABEL-007 | Outbound text carries a confidentiality marker | Deny |
| R-TOOL-003 | A tool that is not on the allowlist | Deny |
| R-RAG-006 | A retrieval source that is not on the approved list | Deny |
| R-SPEND-002 | Spend over the per-action limit | Wait for a human |
| R-DEPLOY-004 | Deploy to production | Wait for a human |
| R-EXTSEND-005 | Message to an external audience | Wait for a human |
| FAIL-CLOSED | Unknown field, missing field, wrong type or unknown action type | Deny |

Deny beats wait for a human, and wait for a human beats allow. If rules disagree, the stricter answer wins. A malformed rules file stops the run (exit 2) and allows nothing.

## Human oversight

Actions that need a person return PENDING with an approval id. The approver must be on the approver list and must be a different person from the requester. The approval is tied to the exact action by sha256 and works once, so it cannot be reused for another action. Each approval, refusal and release is written to the ledger.

## Current results

Reproduced by `bash check.sh`:

| Check | Result |
|---|---|
| Unit tests | 55 tests, all pass |
| Mutation check | 19/19 deliberate breaks caught by a failing test |
| Example actions matching their stated expectation | 15/15 |
| Rules mapped in CONTROLS_MATRIX.md with an existing test | 7/7 |
| Rules with a RISK_REGISTER ticket | 7/7 |
| Ledger chain after the run | intact |

## Known limitations

- The log shows that history was changed. It does not show who wrote it, and removal of the newest entries is caught only if the head hash was recorded somewhere the writer cannot edit.
- The examples are synthetic. The patterns catch common shapes of personal data, not all of it.
- Approver identity is a plain string and approvals live in memory in this reference. A real deployment needs authenticated identities and persistent storage.
- Known action types that match no rule are allowed.
- Framework references (NIST AI RMF 1.0, ISO/IEC 42001:2023, Regulation (EU) 2024/1689) are the author's judgment, for an assessor to accept or change.
- Whether any law applies to a given system, and what must be reported to a regulator, is a decision for qualified legal counsel.

## Where to look next

`README.md` to reproduce the results, `CONTROLS_MATRIX.md` for the mapping, `RISK_REGISTER.md` for the tickets, `INCIDENT_RUNBOOK.md` for what to do when the gate fires.
