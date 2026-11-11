# Controls matrix

One row per technical control. Each row names the code that enforces it, the framework references it supports, the evidence it produces, and the tests that prove it. `src/ci_gate.py` fails the build if a rule in `policies/rules.yaml` has no row here, or if a row names a test that does not exist.

This is a mapping and a set of technical controls. It is not an attestation and not a legal opinion. Mapping is the author's judgment; confirm clause text against the published standard.

## Mapping

| Control | Check (file:function) | What it enforces | NIST AI RMF 1.0 | ISO/IEC 42001:2023 | EU AI Act (Regulation (EU) 2024/1689) | Evidence produced | Test |
|---|---|---|---|---|---|---|---|
| R-PII-001 | `src/policy_gate.py:match_rule` (regex) | Outbound text with an email address or US SSN-shaped number is denied | MEASURE 2.7 | 8.3 | Art. 15 | Ledger entry, decision DENY, rule id R-PII-001 | `test_pii_email_blocked`, `test_pii_ssn_blocked`, `test_pii_clean_text_passes` |
| R-SPEND-002 | `src/policy_gate.py:match_rule` (gt) | Spend over the per-action limit waits for a human; the limit itself is allowed | GOVERN 1.4 | 6.1 | Art. 9 | Ledger entry, decision PENDING, approval id | `test_spend_over_limit_pending`, `test_spend_at_limit_allowed`, `test_spend_under_limit_allowed` |
| R-TOOL-003 | `src/policy_gate.py:match_rule` (in, negate) | A tool not on the allowlist is denied | MEASURE 2.7 | 8.3 | Art. 9, Art. 15 | Ledger entry, decision DENY, rule id R-TOOL-003 | `test_unlisted_tool_denied`, `test_allowlisted_tool_allowed` |
| R-DEPLOY-004 | `src/policy_gate.py:match_rule` (equals) | A production deploy waits for a human sign-off | MAP 3.5 | 8.3 | Art. 14 | Ledger entry, decision PENDING, approval id | `test_production_deploy_pending`, `test_staging_deploy_allowed` |
| R-EXTSEND-005 | `src/policy_gate.py:match_rule` (equals) | A message to an external audience waits for a human sign-off | GOVERN 3.2 | 8.3 | Art. 14 | Ledger entry, decision PENDING, approval id | `test_external_send_pending`, `test_internal_send_allowed` |
| R-RAG-006 | `src/policy_gate.py:match_rule` (in, negate) | Retrieval from a source not on the approved list is denied | GOVERN 1.4 | 8.2 | Art. 10 | Ledger entry, decision DENY, rule id R-RAG-006 | `test_unapproved_rag_source_denied`, `test_approved_rag_source_allowed` |
| R-LABEL-007 | `src/policy_gate.py:match_rule` (contains_any) | Outbound text carrying a confidentiality marker is denied | MEASURE 2.7 | 8.3 | Art. 15 | Ledger entry, decision DENY, rule id R-LABEL-007 | `test_label_marker_denied` |
| Evaluation order and fail-closed | `src/policy_gate.py:evaluate_action` | Deny beats approval beats allow; unknown field, missing field, wrong type or unknown action type is denied; a malformed rules file exits 2 | MANAGE 2.4 | 8.3 | Art. 15 | Ledger entry with rule id FAIL-CLOSED; exit code 2 on bad rules | `test_deny_beats_pending`, `test_precedence_deny_over_pending_over_allow`, `test_unknown_field_denied`, `test_missing_rule_field_denied`, `test_malformed_rules_file_exit_2` |
| Human approval | `src/policy_gate.py:Gate.approve`, `Gate.release` | Approver must differ from requester and be on the approver list; an approval is bound to one action by sha256 and is single use | GOVERN 3.2, MANAGE 2.4 | 8.3 | Art. 14 | Ledger entries APPROVED, RELEASED, APPROVAL_REFUSED, REPLAY_REFUSED | `test_separation_of_duties`, `test_unlisted_approver_refused`, `test_approval_replay_to_different_action_refused`, `test_approval_happy_path_releases_once` |
| Audit ledger | `src/audit_ledger.py:verify`, `Ledger.append` | Append-only hash chain; edit, delete, reorder and insert are detected; tail truncation is detected when the head hash was anchored | MEASURE 2.4, MANAGE 4.1 | 7.5, 9.1 | Art. 12, Art. 19 | `out/ledger.jsonl`; `verify` exit code 0 or 1 | `test_edit_detected`, `test_delete_detected`, `test_reorder_detected`, `test_insert_detected`, `test_sequence_gap_with_valid_hash_detected`, `test_wrong_prev_hash_with_valid_hash_detected`, `test_truncate_tail_needs_anchor`, `test_entry_hash_matches_published_formula` |
| CI gate | `src/ci_gate.py:main` | Build fails if a decision differs from expect, the ledger fails verify, a rule is unmapped, unticketed or never exercised | MANAGE 4.1 | 9.1, 10.2 | Art. 9, Art. 72 | Gate output and exit code | `test_ci_gate_fails_when_rule_removed_from_matrix`, `test_ci_gate_fails_when_ticket_missing`, `test_ci_gate_fails_on_wrong_expectation` |
| Incident process | `INCIDENT_RUNBOOK.md` (document, no code) | Triage, escalation, corrective action log, and a legal decision on serious-incident reporting | MANAGE 4.3 | 10.2 | Art. 72, Art. 73 | Corrective action entries in the runbook log | none, this row is a written procedure |

## Reference ids used

Only these ids are used in this repository. Short names are the author's paraphrase.

| Framework | Ids and short names |
|---|---|
| NIST AI RMF 1.0 | GOVERN 1.4 (risk management process and policies), GOVERN 3.2 (roles for human-AI oversight), MAP 3.5 (human oversight processes), MEASURE 2.4 (monitoring in production), MEASURE 2.7 (security and resilience), MANAGE 2.4 (mechanisms to supersede or disengage), MANAGE 4.1 (post-deployment monitoring and incident response), MANAGE 4.3 (incident tracking and response) |
| ISO/IEC 42001:2023 | 6.1 (actions to address risks and opportunities), 7.5 (documented information), 8.2 (AI risk assessment), 8.3 (AI risk treatment), 9.1 (monitoring, measurement, analysis and evaluation), 10.2 (nonconformity and corrective action) |
| EU AI Act (Regulation (EU) 2024/1689) | Art. 9 (risk management system), Art. 10 (data and data governance), Art. 12 (record-keeping), Art. 14 (human oversight), Art. 15 (accuracy, robustness and cybersecurity), Art. 19 (automatically generated logs), Art. 72 (post-market monitoring), Art. 73 (reporting of serious incidents) |

Mapping is the author's judgment; confirm clause text against the published standard.
