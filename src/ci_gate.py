"""CI/CD compliance gate. Exit 0 only when every check passes.

Checks:
  1. Every example action gets exactly the decision (and rule ids) its `expect` field states.
  2. The audit ledger written by that run verifies, against the head hash seen at write time.
  3. Every rule is exercised by at least one example.
  4. Every rule id appears in CONTROLS_MATRIX.md with a test name that exists in the test file.
  5. Every rule names a RISK_REGISTER ticket whose block lists that rule id.

Exit: 0 green, 1 a check failed, 2 the rules file or the examples are unreadable.
Usage: python3 src/ci_gate.py [--root DIR] [--ledger FILE]
"""
import argparse
import json
import os
import re
import sys

from audit_ledger import Ledger, LedgerError, verify
from policy_gate import Gate, RulesError, load_rules

HERE = os.path.dirname(os.path.abspath(__file__))


def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def check_decisions(rules, actions, ledger):
    """Return (problems, rule ids fired, number of matching actions, head hash written)."""
    problems, seen, fired, matched = [], set(), set(), 0
    gate = Gate(rules, ledger)
    for action in actions:
        expect = action.get("expect") if isinstance(action, dict) else None
        if not isinstance(expect, dict) or "decision" not in expect or "rule_ids" not in expect:
            problems.append("action %s has no usable expect field" % (action.get("id") if isinstance(action, dict) else "?"))
            continue
        d = gate.evaluate(action)
        seen.add(d["outcome"])
        fired.update(d["rule_ids"])
        if d["outcome"] != expect["decision"] or sorted(expect["rule_ids"]) != d["rule_ids"]:
            problems.append("action %s: expected %s %s, got %s %s" % (
                d["action_id"], expect["decision"], sorted(expect["rule_ids"]), d["outcome"], d["rule_ids"]))
        else:
            matched += 1
    for needed in ("ALLOW", "DENY", "PENDING"):
        if needed not in seen:
            problems.append("no example produced %s, the example set is not a real test" % needed)
    return problems, fired, matched, gate.head


def check_matrix(rules, matrix, test_source):
    problems, mapped = [], 0
    for rule in rules["rules"]:
        rows = [l for l in matrix.split("\n") if l.lstrip().startswith("|") and rule["id"] in l]
        names = re.findall(r"test_[a-z0-9_]+", " ".join(rows))
        if not rows:
            problems.append("rule %s is not mapped in CONTROLS_MATRIX.md" % rule["id"])
        elif not names:
            problems.append("rule %s has a matrix row but names no test" % rule["id"])
        else:
            missing = [n for n in names if "def %s(" % n not in test_source]
            if missing:
                problems.append("rule %s names a test that does not exist: %s" % (rule["id"], missing[0]))
            else:
                mapped += 1
    return problems, mapped


def check_register(rules, register):
    problems, ticketed = [], 0
    blocks = {}
    for chunk in re.split(r"(?m)^### ", register)[1:]:
        key = chunk.split("\n", 1)[0].split(" ", 1)[0]
        blocks[key] = chunk
    for rule in rules["rules"]:
        block = blocks.get(rule["ticket"])
        if block is None:
            problems.append("rule %s names ticket %s which is not in RISK_REGISTER.md" % (rule["id"], rule["ticket"]))
        elif rule["id"] not in block:
            problems.append("ticket %s does not list rule %s" % (rule["ticket"], rule["id"]))
        else:
            ticketed += 1
    return problems, ticketed


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ci_gate.py")
    parser.add_argument("--root", default=os.path.dirname(HERE))
    parser.add_argument("--ledger", default=None)
    args = parser.parse_args(argv)
    root = args.root
    ledger_path = args.ledger or os.path.join(root, "out", "ledger.jsonl")
    try:
        rules = load_rules(os.path.join(root, "policies", "rules.yaml"))
        raw = [x for x in read_text(os.path.join(root, "examples", "actions.jsonl")).split("\n") if x.strip()]
        actions = [json.loads(x) for x in raw]
        matrix = read_text(os.path.join(root, "CONTROLS_MATRIX.md"))
        register = read_text(os.path.join(root, "RISK_REGISTER.md"))
        test_source = read_text(os.path.join(root, "tests", "test_compliance.py"))
    except RulesError as exc:
        print("CI GATE: RULES ERROR: %s" % exc)
        return 2
    except (OSError, ValueError) as exc:
        print("CI GATE: INPUT ERROR: %s" % exc)
        return 2
    if not actions:
        print("CI GATE: INPUT ERROR: no example actions")
        return 2

    failures = []
    ledger = Ledger(ledger_path)
    try:
        problems, fired, matched, head = check_decisions(rules, actions, ledger)
    except LedgerError as exc:
        print("CI GATE: LEDGER ERROR: %s" % exc)
        return 2
    failures += problems
    print("CI GATE: decisions match expect: %d/%d" % (matched, len(actions)))

    for rule in rules["rules"]:
        if rule["id"] not in fired:
            failures.append("rule %s is never exercised by examples/actions.jsonl" % rule["id"])

    try:
        ok, bad, reason = verify(ledger_path, expected_head=head)
        if not ok:
            failures.append("ledger failed verify at seq %s: %s" % (bad, reason))
        print("CI GATE: ledger chain intact, head matches the hash written this run: %s" % ("yes" if ok else "NO"))
    except LedgerError as exc:
        failures.append("ledger unreadable after the run: %s" % exc)

    problems, mapped = check_matrix(rules, matrix, test_source)
    failures += problems
    print("CI GATE: rules mapped in CONTROLS_MATRIX.md with an existing test: %d/%d" % (mapped, len(rules["rules"])))

    problems, ticketed = check_register(rules, register)
    failures += problems
    print("CI GATE: rules with a RISK_REGISTER ticket: %d/%d" % (ticketed, len(rules["rules"])))

    if failures:
        for line in failures:
            print("FAIL: %s" % line)
        print("CI GATE: RED (%d failure(s))" % len(failures))
        return 1
    print("CI GATE: GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
