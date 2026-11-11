# Risk register

Jira-style tickets for the risks this repository addresses. Likelihood and impact are the author's 1 to 5 inputs for a fictional organization, not measurements. Severity is likelihood times impact. Owner is a role, not a person. A checked box means the named test passes in `bash check.sh`; the last box on each ticket is a human decision that code cannot make.

`src/ci_gate.py` fails the build if any rule in `policies/rules.yaml` points to a ticket that is missing here or does not list the rule id.

### GRC-101 Shadow AI API use

| Field | Value |
|---|---|
| Type | Risk |
| Summary | An agent calls an AI service or tool nobody reviewed, so data leaves with no contract or log |
| Likelihood x impact | 4 x 4 = 16, High |
| Owner role | Head of Platform Engineering |
| Linked control | R-TOOL-003 |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: tool calls are checked against an allowlist; anything else is denied and logged.

Acceptance criteria:
- [x] A tool not on the allowlist is denied (`test_unlisted_tool_denied`)
- [x] An allowlisted tool is not blocked (`test_allowlisted_tool_allowed`)
- [ ] Risk owner accepts the residual risk in writing

### GRC-102 Unapproved retrieval data source

| Field | Value |
|---|---|
| Type | Risk |
| Summary | A retrieval pipeline ingests an unvetted source, so outputs rest on data nobody governs |
| Likelihood x impact | 3 x 4 = 12, Medium |
| Owner role | Head of Data Governance |
| Linked control | R-RAG-006 |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: ingestion requests name a source; sources not on the approved list are denied and logged.

Acceptance criteria:
- [x] An unapproved source is denied (`test_unapproved_rag_source_denied`)
- [x] An approved source is not blocked (`test_approved_rag_source_allowed`)
- [ ] Data owner confirms the approved source list

### GRC-103 Missing human sign-off on production deploy

| Field | Value |
|---|---|
| Type | Risk |
| Summary | An agent pushes a change to production with no named person approving it |
| Likelihood x impact | 3 x 5 = 15, High |
| Owner role | Head of Engineering |
| Linked control | R-DEPLOY-004 |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: a production deploy returns PENDING with an approval id. A different, listed approver must approve it, and the approval works for that one action only.

Acceptance criteria:
- [x] A production deploy waits for a human (`test_production_deploy_pending`)
- [x] A staging deploy is not blocked (`test_staging_deploy_allowed`)
- [x] The requester cannot approve their own action (`test_separation_of_duties`)
- [ ] Release manager confirms the approver list matches the real on-call roster

### GRC-104 Personal data or confidential material in agent output

| Field | Value |
|---|---|
| Type | Risk |
| Summary | Outbound text contains an email address, an SSN-shaped number or a confidentiality marker |
| Likelihood x impact | 4 x 4 = 16, High |
| Owner role | Privacy Officer |
| Linked control | R-PII-001, R-LABEL-007 |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: outbound text is pattern-checked before send. Patterns catch common shapes only; see Limitations in the README.

Acceptance criteria:
- [x] An email address is denied (`test_pii_email_blocked`)
- [x] An SSN-shaped number is denied (`test_pii_ssn_blocked`)
- [x] A confidentiality marker is denied (`test_label_marker_denied`)
- [x] Clean text is not blocked (`test_pii_clean_text_passes`)
- [ ] Privacy Officer reviews the pattern list for the real data in scope

### GRC-105 Runaway spend

| Field | Value |
|---|---|
| Type | Risk |
| Summary | An agent commits money above a sensible per-action limit with no review |
| Likelihood x impact | 3 x 3 = 9, Medium |
| Owner role | Finance Controller |
| Linked control | R-SPEND-002 |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: spend over the limit returns PENDING and needs a human approver. The limit is a value in the rules file.

Acceptance criteria:
- [x] Spend over the limit waits for a human (`test_spend_over_limit_pending`)
- [x] Spend exactly at the limit is allowed (`test_spend_at_limit_allowed`)
- [ ] Finance Controller sets the real limit and a cumulative cap (a cumulative cap is not built here)

### GRC-106 Audit log tampering

| Field | Value |
|---|---|
| Type | Risk |
| Summary | Someone edits, removes, reorders or adds log entries to hide what an agent did |
| Likelihood x impact | 2 x 5 = 10, Medium |
| Owner role | Head of Internal Audit |
| Linked control | Audit ledger (`src/audit_ledger.py`), no rule id |
| Status | Control implemented in the reference ledger; residual risk not yet accepted |

Mitigation: each entry carries the hash of the one before it. Record the head hash somewhere the writer cannot edit to catch tail truncation and full rewrites.

Acceptance criteria:
- [x] An edited entry is detected (`test_edit_detected`)
- [x] A deleted entry is detected (`test_delete_detected`)
- [x] A reordered pair is detected (`test_reorder_detected`)
- [x] An inserted entry is detected (`test_insert_detected`)
- [x] Tail truncation is detected when the head was anchored (`test_truncate_tail_needs_anchor`)
- [ ] Internal Audit chooses where the head hash is anchored

### GRC-107 Approval replay

| Field | Value |
|---|---|
| Type | Risk |
| Summary | An approval given for one action is reused to release a different or repeated action |
| Likelihood x impact | 2 x 4 = 8, Medium |
| Owner role | Head of Security Engineering |
| Linked control | Human approval (`Gate.approve`, `Gate.release`), no rule id |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: an approval is bound to the sha256 of the action and can be used once.

Acceptance criteria:
- [x] An approval cannot release a different action (`test_approval_replay_to_different_action_refused`)
- [x] An approval cannot be used twice (`test_approval_happy_path_releases_once`)
- [ ] Security Engineering decides how approver identity is authenticated (it is a plain string here)

### GRC-108 External message sent without review

| Field | Value |
|---|---|
| Type | Risk |
| Summary | An agent sends a message outside the organization with no human reading it first |
| Likelihood x impact | 3 x 4 = 12, Medium |
| Owner role | Head of Communications |
| Linked control | R-EXTSEND-005 |
| Status | Control implemented in the reference gate; residual risk not yet accepted |

Mitigation: a message to an external audience returns PENDING and needs a human approver.

Acceptance criteria:
- [x] An external message waits for a human (`test_external_send_pending`)
- [x] An internal message is not blocked (`test_internal_send_allowed`)
- [ ] Communications confirms who counts as an external audience
