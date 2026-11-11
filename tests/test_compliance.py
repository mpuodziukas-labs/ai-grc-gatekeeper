"""Tests for the policy gate, the audit ledger and the CI gate.

Runs under `python3 -m unittest` and under pytest. Standard library only.
"""
import copy
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
sys.dont_write_bytecode = True

import audit_ledger  # noqa: E402
import policy_gate  # noqa: E402

RULES_PATH = os.path.join(ROOT, "policies", "rules.yaml")
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")


def fixed_clock():
    return datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def act(kind, **fields):
    action = {"id": "t-1", "type": kind, "requester": "agent-a"}
    action.update(fields)
    return action


def run(args, cwd=None):
    return subprocess.run([sys.executable] + args, capture_output=True, text=True,
                          cwd=cwd, env=ENV)


def copy_repo(dest):
    target = os.path.join(dest, "repo")
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(
        ".git", "out", "__pycache__", "*.pyc", ".pytest_cache"))
    return target


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.rules = policy_gate.load_rules(RULES_PATH)

    def decide(self, action):
        return policy_gate.evaluate_action(self.rules, action)

    def make_ledger(self, n=4, name="ledger.jsonl"):
        path = os.path.join(self.tmp, name)
        led = audit_ledger.Ledger(path, clock=fixed_clock)
        for i in range(n):
            led.append("agent-a", "send:m-%d" % i, "ALLOW", [])
        return path

    def lines(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().split("\n")[:-1]

    def write_lines(self, path, lines):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


class RuleTests(TmpCase):
    def test_pii_email_blocked(self):
        d = self.decide(act("send", audience="internal", text="mail jane.doe@example.com"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertIn("R-PII-001", d["rule_ids"])

    def test_pii_ssn_blocked(self):
        d = self.decide(act("send", audience="internal", text="id 123-45-6789 on file"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertIn("R-PII-001", d["rule_ids"])

    def test_pii_clean_text_passes(self):
        d = self.decide(act("send", audience="internal", text="Quarterly summary attached."))
        self.assertEqual(d["outcome"], "ALLOW")
        self.assertEqual(d["rule_ids"], [])

    def test_spend_over_limit_pending(self):
        d = self.decide(act("spend", amount_usd=2500))
        self.assertEqual(d["outcome"], "PENDING")
        self.assertEqual(d["rule_ids"], ["R-SPEND-002"])

    def test_spend_at_limit_allowed(self):
        self.assertEqual(self.decide(act("spend", amount_usd=500))["outcome"], "ALLOW")

    def test_spend_under_limit_allowed(self):
        self.assertEqual(self.decide(act("spend", amount_usd=120))["outcome"], "ALLOW")

    def test_unlisted_tool_denied(self):
        d = self.decide(act("tool_call", tool="unvetted_llm_api"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertEqual(d["rule_ids"], ["R-TOOL-003"])

    def test_allowlisted_tool_allowed(self):
        self.assertEqual(self.decide(act("tool_call", tool="search_docs"))["outcome"], "ALLOW")

    def test_production_deploy_pending(self):
        d = self.decide(act("deploy", environment="production"))
        self.assertEqual(d["outcome"], "PENDING")
        self.assertEqual(d["rule_ids"], ["R-DEPLOY-004"])

    def test_staging_deploy_allowed(self):
        self.assertEqual(self.decide(act("deploy", environment="staging"))["outcome"], "ALLOW")

    def test_external_send_pending(self):
        d = self.decide(act("send", audience="external", text="Release notes attached."))
        self.assertEqual(d["outcome"], "PENDING")
        self.assertEqual(d["rule_ids"], ["R-EXTSEND-005"])

    def test_internal_send_allowed(self):
        d = self.decide(act("send", audience="internal", text="Release notes attached."))
        self.assertEqual(d["outcome"], "ALLOW")

    def test_unapproved_rag_source_denied(self):
        d = self.decide(act("rag_ingest", source="scraped-forum"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertEqual(d["rule_ids"], ["R-RAG-006"])

    def test_approved_rag_source_allowed(self):
        d = self.decide(act("rag_ingest", source="internal-policy-wiki"))
        self.assertEqual(d["outcome"], "ALLOW")

    def test_label_marker_denied(self):
        d = self.decide(act("send", audience="internal", text="Draft. Confidential: board only"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertEqual(d["rule_ids"], ["R-LABEL-007"])

    def test_deny_beats_pending(self):
        d = self.decide(act("send", audience="external", text="write to a@example.com"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertEqual(d["rule_ids"], ["R-EXTSEND-005", "R-PII-001"])

    def test_precedence_deny_over_pending_over_allow(self):
        def rule(rid, effect):
            return {"id": rid, "title": rid, "severity": "low", "ticket": "GRC-1",
                    "effect": effect, "applies_to": ["deploy"],
                    "match": {"field": "environment", "op": "equals", "value": "production"}}
        base = {"version": 1, "approvers": ["boss"], "action_types": ["deploy"],
                "known_fields": ["environment"]}
        both = dict(base, rules=[rule("A", "allow"), rule("D", "deny")])
        only_pending = dict(base, rules=[rule("A", "allow"), rule("H", "require_human_approval")])
        only_allow = dict(base, rules=[rule("A", "allow")])
        action = act("deploy", environment="production")
        self.assertEqual(policy_gate.evaluate_action(
            policy_gate.validate_rules(both), action)["outcome"], "DENY")
        self.assertEqual(policy_gate.evaluate_action(
            policy_gate.validate_rules(only_pending), action)["outcome"], "PENDING")
        self.assertEqual(policy_gate.evaluate_action(
            policy_gate.validate_rules(only_allow), action)["outcome"], "ALLOW")


class FailClosedTests(TmpCase):
    def test_unknown_field_denied(self):
        d = self.decide(act("tool_call", tool="search_docs", shell_cmd="ls"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertEqual(d["rule_ids"], ["FAIL-CLOSED"])

    def test_missing_rule_field_denied(self):
        d = self.decide(act("send", text="no audience given"))
        self.assertEqual(d["outcome"], "DENY")
        self.assertEqual(d["rule_ids"], ["FAIL-CLOSED"])

    def test_unknown_action_type_denied(self):
        self.assertEqual(self.decide(act("teleport"))["outcome"], "DENY")

    def test_wrong_value_type_denied(self):
        self.assertEqual(self.decide(act("spend", amount_usd="9999"))["outcome"], "DENY")

    def test_non_object_action_denied(self):
        self.assertEqual(self.decide(["not", "an", "object"])["outcome"], "DENY")

    def test_malformed_rules_file_exit_2(self):
        bad = os.path.join(self.tmp, "bad.yaml")
        with open(bad, "w") as fh:
            fh.write("{ this is not json")
        res = run([os.path.join(SRC, "policy_gate.py"), "evaluate",
                   os.path.join(ROOT, "examples", "actions.jsonl"), "--rules", bad,
                   "--ledger", os.path.join(self.tmp, "l.jsonl")])
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertNotIn("ALLOW", res.stdout)

    def test_missing_rules_file_exit_2(self):
        res = run([os.path.join(SRC, "policy_gate.py"), "evaluate",
                   os.path.join(ROOT, "examples", "actions.jsonl"),
                   "--rules", os.path.join(self.tmp, "absent.yaml"),
                   "--ledger", os.path.join(self.tmp, "l.jsonl")])
        self.assertEqual(res.returncode, 2)

    def test_invalid_rule_schema_rejected(self):
        with open(RULES_PATH, encoding="utf-8") as fh:
            good = json.load(fh)
        bad_effect = copy.deepcopy(good)
        bad_effect["rules"][0]["effect"] = "permit"
        bad_regex = copy.deepcopy(good)
        bad_regex["rules"][0]["match"] = {"field": "text", "op": "regex", "value": "("}
        bad_op = copy.deepcopy(good)
        bad_op["rules"][0]["match"]["op"] = "startswith"
        no_approvers = copy.deepcopy(good)
        no_approvers["approvers"] = []
        for broken in (bad_effect, bad_regex, bad_op, no_approvers):
            with self.assertRaises(policy_gate.RulesError):
                policy_gate.validate_rules(broken)

    def test_cli_prints_one_line_per_action_and_summary(self):
        ledger = os.path.join(self.tmp, "l.jsonl")
        res = run([os.path.join(SRC, "policy_gate.py"), "evaluate",
                   os.path.join(ROOT, "examples", "actions.jsonl"), "--ledger", ledger])
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        out = res.stdout.strip().split("\n")
        with open(os.path.join(ROOT, "examples", "actions.jsonl"), encoding="utf-8") as fh:
            n = len([x for x in fh.read().split("\n") if x.strip()])
        self.assertEqual(len(out), n + 1)
        self.assertTrue(out[-1].startswith("SUMMARY total=%d " % n), out[-1])
        self.assertEqual(len(self.lines(ledger)), n)


class LedgerTests(TmpCase):
    def test_intact_ledger_verifies(self):
        ok, bad, reason = audit_ledger.verify(self.make_ledger())
        self.assertTrue(ok, reason)
        self.assertIsNone(bad)

    def test_entry_hash_matches_published_formula(self):
        path = self.make_ledger(2)
        first, second = [json.loads(x) for x in self.lines(path)]
        self.assertEqual(first["prev_hash"], "0" * 64)
        self.assertEqual(second["prev_hash"], first["hash"])
        body = {k: v for k, v in second.items() if k != "hash"}
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(second["hash"], hashlib.sha256(blob).hexdigest())

    def test_clock_is_injectable_and_rfc3339_utc(self):
        first = json.loads(self.lines(self.make_ledger(1))[0])
        self.assertEqual(first["ts"], "2026-01-01T12:00:00Z")
        self.assertEqual(first["seq"], 1)

    def test_append_never_rewrites_existing_lines(self):
        path = self.make_ledger(3)
        with open(path, "rb") as fh:
            before = fh.read()
        audit_ledger.Ledger(path, clock=fixed_clock).append("agent-a", "x", "ALLOW", [])
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertTrue(after.startswith(before))
        self.assertEqual(len(after.split(b"\n")) - 1, 4)

    def test_edit_detected(self):
        path = self.make_ledger()
        lines = self.lines(path)
        lines[1] = lines[1].replace("agent-a", "agent-b")
        self.write_lines(path, lines)
        ok, bad, _ = audit_ledger.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)

    def test_delete_detected(self):
        path = self.make_ledger()
        lines = self.lines(path)
        del lines[1]
        self.write_lines(path, lines)
        ok, bad, _ = audit_ledger.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)

    def test_reorder_detected(self):
        path = self.make_ledger()
        lines = self.lines(path)
        lines[1], lines[2] = lines[2], lines[1]
        self.write_lines(path, lines)
        ok, bad, _ = audit_ledger.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)

    def test_insert_detected(self):
        path = self.make_ledger()
        lines = self.lines(path)
        prev = json.loads(lines[0])["hash"]
        forged = {"seq": 2, "ts": "2026-01-01T12:00:00Z", "actor": "intruder",
                  "action": "send:forged", "decision": "ALLOW", "rule_ids": [],
                  "prev_hash": prev}
        forged["hash"] = audit_ledger.entry_hash(forged)
        lines.insert(1, audit_ledger.canonical(forged))
        self.write_lines(path, lines)
        ok, bad, _ = audit_ledger.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 3)

    def _replace_line(self, path, index, **changes):
        """Rewrite one entry with fresh, correct self-hash so only the named field is wrong."""
        lines = self.lines(path)
        entry = json.loads(lines[index])
        entry.update(changes)
        entry["hash"] = audit_ledger.entry_hash(entry)
        lines[index] = audit_ledger.canonical(entry)
        self.write_lines(path, lines)

    def test_sequence_gap_with_valid_hash_detected(self):
        path = self.make_ledger(2)
        self._replace_line(path, 1, seq=7)
        ok, bad, reason = audit_ledger.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)
        self.assertIn("sequence", reason)

    def test_wrong_prev_hash_with_valid_hash_detected(self):
        path = self.make_ledger(3)
        self._replace_line(path, 1, prev_hash="0" * 64)
        ok, bad, reason = audit_ledger.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)
        self.assertIn("prev_hash", reason)

    def test_truncate_tail_needs_anchor(self):
        path = self.make_ledger()
        head = json.loads(self.lines(path)[-1])["hash"]
        self.write_lines(path, self.lines(path)[:-1])
        self.assertTrue(audit_ledger.verify(path)[0])
        ok, _, reason = audit_ledger.verify(path, expected_head=head)
        self.assertFalse(ok)
        self.assertIn("anchor", reason)

    def test_partial_line_is_malformed(self):
        path = self.make_ledger()
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(data[:-20])
        with self.assertRaises(audit_ledger.LedgerError):
            audit_ledger.verify(path)

    def test_full_chain_rewrite_caught_only_by_anchor(self):
        path = self.make_ledger()
        head = json.loads(self.lines(path)[-1])["hash"]
        forged = os.path.join(self.tmp, "forged.jsonl")
        led = audit_ledger.Ledger(forged, clock=fixed_clock)
        for i in range(4):
            led.append("agent-z", "send:m-%d" % i, "ALLOW", [])
        self.assertTrue(audit_ledger.verify(forged)[0])
        self.assertFalse(audit_ledger.verify(forged, expected_head=head)[0])

    def test_cli_exit_codes(self):
        cli = os.path.join(SRC, "audit_ledger.py")
        path = self.make_ledger()
        self.assertEqual(run([cli, "verify", path]).returncode, 0)
        lines = self.lines(path)
        lines[2] = lines[2].replace("ALLOW", "DENY!")
        tampered = os.path.join(self.tmp, "t.jsonl")
        self.write_lines(tampered, lines)
        self.assertEqual(run([cli, "verify", tampered]).returncode, 1)
        self.assertEqual(run([cli, "verify", os.path.join(self.tmp, "absent")]).returncode, 2)
        junk = os.path.join(self.tmp, "junk.jsonl")
        with open(junk, "w") as fh:
            fh.write("not json\n")
        self.assertEqual(run([cli, "verify", junk]).returncode, 2)
        empty = os.path.join(self.tmp, "empty.jsonl")
        open(empty, "w").close()
        self.assertEqual(run([cli, "verify", empty]).returncode, 2)


class ApprovalTests(TmpCase):
    def gate(self):
        led = audit_ledger.Ledger(os.path.join(self.tmp, "l.jsonl"), clock=fixed_clock)
        return policy_gate.Gate(self.rules, led)

    def pending(self, gate, requester="agent-a"):
        action = act("deploy", environment="production", requester=requester)
        d = gate.evaluate(action)
        self.assertEqual(d["outcome"], "PENDING")
        self.assertTrue(d["approval_id"])
        return action, d["approval_id"]

    def test_approval_happy_path_releases_once(self):
        gate = self.gate()
        action, aid = self.pending(gate)
        self.assertTrue(gate.approve(aid, "risk-officer")[0])
        self.assertTrue(gate.release(aid, action)[0])
        self.assertFalse(gate.release(aid, action)[0])

    def test_separation_of_duties(self):
        gate = self.gate()
        action, aid = self.pending(gate, requester="security-lead")
        ok, reason = gate.approve(aid, "security-lead")
        self.assertFalse(ok)
        self.assertIn("separation", reason)
        self.assertFalse(gate.release(aid, action)[0])

    def test_unlisted_approver_refused(self):
        gate = self.gate()
        _, aid = self.pending(gate)
        ok, reason = gate.approve(aid, "some-other-agent")
        self.assertFalse(ok)
        self.assertIn("not an approver", reason)

    def test_unknown_approval_id_refused(self):
        self.assertFalse(self.gate().approve("APR-9999", "risk-officer")[0])

    def test_approval_replay_to_different_action_refused(self):
        gate = self.gate()
        action, aid = self.pending(gate)
        gate.approve(aid, "risk-officer")
        other = act("deploy", environment="production", id="t-2")
        ok, reason = gate.release(aid, other)
        self.assertFalse(ok)
        self.assertIn("different action", reason)
        self.assertTrue(gate.release(aid, action)[0])

    def test_release_requires_approval_first(self):
        gate = self.gate()
        action, aid = self.pending(gate)
        self.assertFalse(gate.release(aid, action)[0])

    def test_every_decision_and_approval_event_is_logged(self):
        gate = self.gate()
        action, aid = self.pending(gate)
        gate.evaluate(act("tool_call", tool="search_docs", id="t-3"))
        gate.approve(aid, "risk-officer")
        gate.release(aid, action)
        path = os.path.join(self.tmp, "l.jsonl")
        entries = [json.loads(x) for x in self.lines(path)]
        self.assertEqual([e["decision"] for e in entries],
                         ["PENDING", "ALLOW", "APPROVED", "RELEASED"])
        self.assertEqual(entries[0]["rule_ids"], ["R-DEPLOY-004"])
        self.assertTrue(audit_ledger.verify(path)[0])


class CiGateTests(TmpCase):
    def ci(self, repo):
        ledger = os.path.join(self.tmp, "ci_ledger.jsonl")
        return run([os.path.join(repo, "src", "ci_gate.py"), "--ledger", ledger])

    def edit(self, path, fn):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        new = fn(text)
        self.assertNotEqual(text, new, "edit changed nothing")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)

    def test_ci_gate_green_on_clean_copy(self):
        res = self.ci(copy_repo(self.tmp))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("CI GATE: GREEN", res.stdout)

    def test_ci_gate_fails_when_rule_removed_from_matrix(self):
        repo = copy_repo(self.tmp)
        self.edit(os.path.join(repo, "CONTROLS_MATRIX.md"),
                  lambda t: "\n".join(l for l in t.split("\n") if "R-PII-001" not in l))
        res = self.ci(repo)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("R-PII-001", res.stdout)

    def test_ci_gate_fails_when_matrix_names_missing_test(self):
        repo = copy_repo(self.tmp)
        self.edit(os.path.join(repo, "CONTROLS_MATRIX.md"),
                  lambda t: t.replace("test_unlisted_tool_denied", "test_does_not_exist", 1))
        self.assertEqual(self.ci(repo).returncode, 1)

    def test_ci_gate_fails_when_ticket_missing(self):
        repo = copy_repo(self.tmp)
        self.edit(os.path.join(repo, "RISK_REGISTER.md"),
                  lambda t: t.replace("R-RAG-006", "R-REMOVED"))
        res = self.ci(repo)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("R-RAG-006", res.stdout)

    def test_ci_gate_fails_on_wrong_expectation(self):
        repo = copy_repo(self.tmp)
        self.edit(os.path.join(repo, "examples", "actions.jsonl"),
                  lambda t: t.replace('"decision":"DENY"', '"decision":"ALLOW"', 1))
        self.assertEqual(self.ci(repo).returncode, 1)

    def test_ci_gate_fails_on_malformed_rules(self):
        repo = copy_repo(self.tmp)
        with open(os.path.join(repo, "policies", "rules.yaml"), "w") as fh:
            fh.write("{ broken")
        self.assertEqual(self.ci(repo).returncode, 2)

    def test_ci_gate_fails_when_a_rule_is_never_exercised(self):
        repo = copy_repo(self.tmp)
        path = os.path.join(repo, "examples", "actions.jsonl")
        self.edit(path, lambda t: "\n".join(
            l for l in t.split("\n") if "R-LABEL-007" not in l))
        res = self.ci(repo)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("R-LABEL-007", res.stdout)

    def test_ci_gate_ledger_is_intact_after_run(self):
        repo = copy_repo(self.tmp)
        self.assertEqual(self.ci(repo).returncode, 0)
        ledger = os.path.join(self.tmp, "ci_ledger.jsonl")
        self.assertTrue(audit_ledger.verify(ledger)[0])


if __name__ == "__main__":
    unittest.main()
