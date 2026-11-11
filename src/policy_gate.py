"""Policy gate: deterministic rules over agent actions, fail-closed, with human approval.

Precedence: deny beats require_human_approval beats allow. Anything the gate
cannot evaluate (unknown field, missing field, wrong type, unknown action type)
is denied with the rule id FAIL-CLOSED. A malformed rules file exits 2 and
never allows anything.

CLI:  python3 src/policy_gate.py evaluate ACTIONS.jsonl [--rules FILE] [--ledger FILE]
"""
import argparse
import hashlib
import json
import os
import re
import sys

from audit_ledger import Ledger, LedgerError, canonical

EXIT_OK = 0
EXIT_BAD_RULES = 2
EFFECTS = ("deny", "require_human_approval", "allow")
OPS = ("equals", "in", "gt", "contains_any", "regex")
SEVERITIES = ("low", "medium", "high", "critical")
BASE_FIELDS = {"id", "type", "requester", "expect"}
FAIL_CLOSED = "FAIL-CLOSED"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


class RulesError(Exception):
    """The rules file is unreadable or does not follow the schema."""


class InputError(Exception):
    """The actions file is unreadable or has a line that is not JSON."""


class CannotEvaluate(Exception):
    """An action cannot be judged by a rule; the gate denies it."""


def _need(cond, message):
    if not cond:
        raise RulesError(message)


def _is_str_list(value):
    return isinstance(value, list) and value and all(isinstance(x, str) and x for x in value)


def validate_rules(data):
    _need(isinstance(data, dict), "rules file must be a JSON object")
    _need(data.get("version") == 1, "version must be 1")
    for key in ("approvers", "action_types", "known_fields"):
        _need(_is_str_list(data.get(key)), "%s must be a non-empty list of strings" % key)
    rules = data.get("rules")
    _need(isinstance(rules, list) and rules, "rules must be a non-empty list")
    seen = set()
    for rule in rules:
        _need(isinstance(rule, dict), "each rule must be an object")
        rid = rule.get("id")
        _need(isinstance(rid, str) and rid, "rule without an id")
        _need(rid not in seen and rid != FAIL_CLOSED, "duplicate or reserved rule id %s" % rid)
        seen.add(rid)
        for key in ("title", "ticket"):
            _need(isinstance(rule.get(key), str) and rule[key], "%s: missing %s" % (rid, key))
        _need(rule.get("severity") in SEVERITIES, "%s: bad severity" % rid)
        _need(rule.get("effect") in EFFECTS, "%s: bad effect" % rid)
        _need(_is_str_list(rule.get("applies_to")), "%s: applies_to must be a list" % rid)
        _need(set(rule["applies_to"]) <= set(data["action_types"]),
              "%s: applies_to names an unknown action type" % rid)
        match = rule.get("match")
        _need(isinstance(match, dict), "%s: match must be an object" % rid)
        _need(isinstance(match.get("field"), str) and match["field"], "%s: match.field" % rid)
        _need(match["field"] in data["known_fields"], "%s: match.field is not a known field" % rid)
        _need(match.get("op") in OPS, "%s: bad operator" % rid)
        _need("value" in match, "%s: match.value missing" % rid)
        _need(isinstance(match.get("negate", False), bool), "%s: negate must be true or false" % rid)
        op, value = match["op"], match["value"]
        if op in ("in", "contains_any"):
            _need(_is_str_list(value), "%s: value must be a list of strings" % rid)
        if op == "gt":
            _need(isinstance(value, (int, float)) and not isinstance(value, bool),
                  "%s: gt needs a number" % rid)
        if op == "regex":
            _need(isinstance(value, str), "%s: regex needs a string" % rid)
            try:
                rule["_re"] = re.compile(value)
            except re.error as exc:
                raise RulesError("%s: invalid regex: %s" % (rid, exc))
    return data


def load_rules(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise RulesError("cannot read rules file: %s" % exc)
    return validate_rules(data)


def action_hash(action):
    body = {k: v for k, v in action.items() if k != "expect"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def match_rule(rule, action):
    """True or False. Raises CannotEvaluate when the field is missing or the wrong type."""
    match = rule["match"]
    field = match["field"]
    if field not in action:
        raise CannotEvaluate("field %s is required by %s but missing" % (field, rule["id"]))
    actual, op, value = action[field], match["op"], match["value"]
    if op == "equals":
        hit = actual == value
    elif op == "in":
        hit = actual in value
    elif op == "gt":
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            raise CannotEvaluate("field %s must be a number for %s" % (field, rule["id"]))
        hit = actual > value
    else:
        if not isinstance(actual, str):
            raise CannotEvaluate("field %s must be text for %s" % (field, rule["id"]))
        if op == "contains_any":
            hit = any(item.lower() in actual.lower() for item in value)
        else:
            hit = rule["_re"].search(actual) is not None
    if match.get("negate", False):
        hit = not hit
    return hit


def _result(action_id, kind, requester, ahash, outcome, rule_ids, reasons):
    return {"action_id": action_id, "type": kind, "requester": requester, "action_hash": ahash,
            "outcome": outcome, "rule_ids": rule_ids, "reasons": reasons, "approval_id": None}


def evaluate_action(rules, action):
    if not isinstance(action, dict):
        return _result("?", "?", "unknown", hashlib.sha256(canonical(action).encode("utf-8")).hexdigest(),
                       "DENY", [FAIL_CLOSED], ["action is not a JSON object"])
    ahash = action_hash(action)
    aid = str(action.get("id", "?"))
    kind = str(action.get("type", "?"))
    who = str(action.get("requester", "unknown"))

    def closed(reason):
        return _result(aid, kind, who, ahash, "DENY", [FAIL_CLOSED], [reason])

    unknown = sorted(k for k in action if k not in BASE_FIELDS | set(rules["known_fields"]))
    if unknown:
        return closed("unknown field(s): %s" % ", ".join(unknown))
    for key in ("id", "type", "requester"):
        if not isinstance(action.get(key), str) or not action[key]:
            return closed("required field %s is missing or empty" % key)
    if action["type"] not in rules["action_types"]:
        return closed("unknown action type: %s" % action["type"])
    matched = []
    for rule in rules["rules"]:
        if action["type"] not in rule["applies_to"]:
            continue
        try:
            if match_rule(rule, action):
                matched.append(rule)
        except CannotEvaluate as exc:
            return closed(str(exc))
    effects = {r["effect"] for r in matched}
    if "deny" in effects:
        outcome = "DENY"
    elif "require_human_approval" in effects:
        outcome = "PENDING"
    else:
        outcome = "ALLOW"
    return _result(aid, kind, who, ahash, outcome, sorted(r["id"] for r in matched),
                   [r["title"] for r in matched])


class Gate:
    """Evaluates actions, tracks human approvals, and logs every event to the ledger."""

    def __init__(self, rules, ledger):
        self.rules = rules
        self.ledger = ledger
        self._approvals = {}
        self._count = 0
        self.head = None

    def _log(self, actor, label, decision, rule_ids):
        self.head = self.ledger.append(actor, label, decision, rule_ids)["hash"]

    def evaluate(self, action):
        decision = evaluate_action(self.rules, action)
        if decision["outcome"] == "PENDING":
            self._count += 1
            approval_id = "APR-%04d-%s" % (self._count, decision["action_hash"][:8])
            decision["approval_id"] = approval_id
            self._approvals[approval_id] = {"action_hash": decision["action_hash"],
                                            "requester": decision["requester"], "status": "pending"}
        label = "%s:%s:%s" % (decision["type"], decision["action_id"], decision["action_hash"])
        self._log(decision["requester"], label, decision["outcome"], decision["rule_ids"])
        return decision

    def _refuse(self, actor, approval_id, decision, reason):
        self._log(actor, "approval:%s" % approval_id, decision, [])
        return False, reason

    def approve(self, approval_id, approver):
        rec = self._approvals.get(approval_id)
        if rec is None or rec["status"] != "pending":
            return self._refuse(approver, approval_id, "APPROVAL_REFUSED",
                                "no pending approval with that id")
        if approver == rec["requester"]:
            return self._refuse(approver, approval_id, "APPROVAL_REFUSED",
                                "separation of duties: requester cannot approve own action")
        if approver not in self.rules["approvers"]:
            return self._refuse(approver, approval_id, "APPROVAL_REFUSED",
                                "%s is not an approver" % approver)
        rec["status"] = "approved"
        self._log(approver, "approval:%s" % approval_id, "APPROVED", [])
        return True, "approved"

    def release(self, approval_id, action):
        rec = self._approvals.get(approval_id)
        if rec is None or rec["status"] != "approved":
            return self._refuse("gate", approval_id, "APPROVAL_REFUSED", "approval is not in approved state")
        if action_hash(action) != rec["action_hash"]:
            return self._refuse("gate", approval_id, "REPLAY_REFUSED",
                                "approval was granted for a different action")
        rec["status"] = "used"
        self._log("gate", "approval:%s" % approval_id, "RELEASED", [])
        return True, "released"


def read_actions(path):
    try:
        with open(path, encoding="utf-8") as fh:
            rows = [x for x in fh.read().split("\n") if x.strip()]
        return [json.loads(x) for x in rows]
    except (OSError, ValueError) as exc:
        raise InputError("cannot read actions: %s" % exc)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="policy_gate.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ev = sub.add_parser("evaluate")
    ev.add_argument("actions")
    ev.add_argument("--rules", default=os.path.join(ROOT, "policies", "rules.yaml"))
    ev.add_argument("--ledger", default=os.path.join(ROOT, "out", "ledger.jsonl"))
    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
    except RulesError as exc:
        print("RULES ERROR: %s (nothing evaluated, nothing allowed)" % exc)
        return EXIT_BAD_RULES
    try:
        actions = read_actions(args.actions)
    except InputError as exc:
        print("INPUT ERROR: %s" % exc)
        return 2
    if not actions:
        print("INPUT ERROR: no actions to evaluate")
        return 2
    gate = Gate(rules, Ledger(args.ledger))
    counts = {"ALLOW": 0, "DENY": 0, "PENDING": 0}
    try:
        for action in actions:
            d = gate.evaluate(action)
            counts[d["outcome"]] += 1
            tail = " approval=%s" % d["approval_id"] if d["approval_id"] else ""
            print("%-8s %-8s %s%s" % (d["outcome"], d["action_id"], ",".join(d["rule_ids"]) or "-", tail))
    except LedgerError as exc:
        print("LEDGER ERROR: %s" % exc)
        return 2
    print("SUMMARY total=%d allow=%d deny=%d pending=%d" % (
        len(actions), counts["ALLOW"], counts["DENY"], counts["PENDING"]))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
