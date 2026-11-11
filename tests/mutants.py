"""Mutation check: break the controls on purpose and confirm the tests notice.

Copies the repository to a temp directory, runs the tests on the untouched copy
(must pass), then applies each named mutation to a fresh copy and runs the tests
again (must fail). Prints `mutants K/N killed`. Exit 0 only if K == N and N >= 10.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

# (name, file, exact old text, new text). The old text must appear exactly once.
MUTANTS = [
    ("deny downgraded to allow", "src/policy_gate.py",
     'if "deny" in effects:', "if False:"),
    ("prev_hash left out of the entry hash", "src/audit_ledger.py",
     'HASH_EXCLUDE = ("hash",)', 'HASH_EXCLUDE = ("hash", "prev_hash")'),
    ("separation of duties removed", "src/policy_gate.py",
     'if approver == rec["requester"]:', "if False:"),
    ("unknown-field fail-closed removed", "src/policy_gate.py",
     "if unknown:", "if False:"),
    ("ci_gate always exits 0", "src/ci_gate.py",
     "len(failures))\n        return 1", "len(failures))\n        return 0"),
    ("regex operator disabled", "src/policy_gate.py",
     'hit = rule["_re"].search(actual) is not None', "hit = False"),
    ("approver list check removed", "src/policy_gate.py",
     'if approver not in self.rules["approvers"]:', "if False:"),
    ("approval replay binding removed", "src/policy_gate.py",
     'if action_hash(action) != rec["action_hash"]:', "if False:"),
    ("ledger sequence check removed", "src/audit_ledger.py",
     'if entry["seq"] != pos:', "if False:"),
    ("ledger prev_hash link check removed", "src/audit_ledger.py",
     'if entry["prev_hash"] != prev:', "if False:"),
    ("ledger hash recompute removed", "src/audit_ledger.py",
     'if entry_hash(entry) != entry["hash"]:', "if False:"),
    ("malformed rules exit code changed to 0", "src/policy_gate.py",
     "EXIT_BAD_RULES = 2", "EXIT_BAD_RULES = 0"),
    ("controls matrix check skipped", "src/ci_gate.py",
     "problems, mapped = check_matrix(rules, matrix, test_source)",
     'problems, mapped = [], len(rules["rules"])'),
    ("spend limit off by one (gt becomes gte)", "src/policy_gate.py",
     "hit = actual > value", "hit = actual >= value"),
    ("negate flag ignored", "src/policy_gate.py",
     'if match.get("negate", False):', "if False:"),
    ("head anchor check removed", "src/audit_ledger.py",
     "if expected_head is not None and prev != expected_head:", "if False:"),
    ("ledger append forgets the previous hash", "src/audit_ledger.py",
     "seq, prev = self._tail()", "seq, prev = self._tail()[0], GENESIS"),
    ("unexercised-rule check removed", "src/ci_gate.py",
     'if rule["id"] not in fired:', "if False:"),
    ("missing-field fail-closed removed", "src/policy_gate.py",
     'raise CannotEvaluate("field %s is required by %s but missing" % (field, rule["id"]))',
     "return False"),
]


def fresh_copy(dest):
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        ".git", "out", "__pycache__", "*.pyc", ".pytest_cache"))


def run_tests(repo):
    res = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-f"],
                         cwd=repo, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         universal_newlines=True, timeout=600)
    return res.returncode == 0, res.stdout


def main():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "base")
        fresh_copy(base)
        ok, out = run_tests(base)
        if not ok:
            print("BASELINE FAILED: the unmutated copy does not pass its own tests")
            print(out[-2000:])
            return 1
        print("baseline: unmutated copy passes")
        killed = 0
        for i, (name, rel, old, new) in enumerate(MUTANTS):
            repo = os.path.join(tmp, "m%d" % i)
            fresh_copy(repo)
            path = os.path.join(repo, rel)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            if text.count(old) != 1:
                print("MUTATION NOT APPLIED (%d matches): %s" % (text.count(old), name))
                return 1
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text.replace(old, new))
            passed, _ = run_tests(repo)
            print("  %-8s %s" % ("SURVIVED" if passed else "killed", name))
            killed += 0 if passed else 1
    total = len(MUTANTS)
    print("mutants %d/%d killed" % (killed, total))
    return 0 if killed == total and total >= 10 else 1


if __name__ == "__main__":
    sys.exit(main())
