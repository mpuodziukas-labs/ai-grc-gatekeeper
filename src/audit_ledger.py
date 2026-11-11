"""Append-only, hash-chained audit ledger (JSON Lines).

Integrity, not authenticity: the chain shows that a past entry was changed,
removed, reordered or inserted. It does not show who wrote an entry (there is
no signature), and it cannot see entries cut off the end unless the head hash
was recorded somewhere the writer cannot edit.

CLI:  python3 src/audit_ledger.py verify FILE [--head HASH]
Exit: 0 intact, 1 tampered, 2 unreadable or malformed.
"""
import datetime
import hashlib
import json
import os
import sys

GENESIS = "0" * 64
FIELDS = {"seq", "ts", "actor", "action", "decision", "rule_ids", "prev_hash", "hash"}
HASH_EXCLUDE = ("hash",)


class LedgerError(Exception):
    """The ledger cannot be read, or a line is not a well-formed entry."""


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def entry_hash(entry):
    """sha256 over canonical JSON of the entry without its hash (prev_hash included)."""
    body = {k: v for k, v in entry.items() if k not in HASH_EXCLUDE}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class Ledger:
    def __init__(self, path, clock=None):
        self.path = path
        self.clock = clock or _utc_now

    def _tail(self):
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return 0, GENESIS
        with open(self.path, encoding="utf-8") as fh:
            last = [x for x in fh.read().split("\n") if x][-1]
        try:
            entry = json.loads(last)
            return entry["seq"], entry["hash"]
        except (ValueError, KeyError, TypeError):
            raise LedgerError("cannot append: last line of %s is malformed" % self.path)

    def append(self, actor, action, decision, rule_ids):
        stamp = self.clock()
        if stamp.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        seq, prev = self._tail()
        entry = {
            "seq": seq + 1,
            "ts": stamp.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": actor,
            "action": action,
            "decision": decision,
            "rule_ids": list(rule_ids),
            "prev_hash": prev,
        }
        entry["hash"] = entry_hash(entry)
        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry


def _read_lines(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise LedgerError("unreadable: %s" % exc)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise LedgerError("empty ledger")
    return lines


def verify(path, expected_head=None):
    """Return (ok, first_bad_seq, reason). Raises LedgerError if unreadable or malformed."""
    lines = _read_lines(path)
    prev = GENESIS
    for pos, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except ValueError:
            raise LedgerError("line %d is not valid JSON" % pos)
        if not isinstance(entry, dict) or set(entry) != FIELDS:
            raise LedgerError("line %d does not have the entry fields" % pos)
        if (not isinstance(entry["seq"], int) or not isinstance(entry["hash"], str)
                or not isinstance(entry["prev_hash"], str) or not isinstance(entry["rule_ids"], list)):
            raise LedgerError("line %d has a field of the wrong type" % pos)
        if entry["seq"] != pos:
            return False, pos, "sequence break: expected seq %d, found %d" % (pos, entry["seq"])
        if entry["prev_hash"] != prev:
            return False, pos, "prev_hash does not match the previous entry"
        if entry_hash(entry) != entry["hash"]:
            return False, pos, "hash mismatch: entry content was changed"
        prev = entry["hash"]
    if expected_head is not None and prev != expected_head:
        return False, len(lines), "head hash differs from the anchor: entries removed or replaced"
    return True, None, "ok"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    head = None
    if "--head" in argv:
        i = argv.index("--head")
        try:
            head = argv[i + 1]
        except IndexError:
            print("usage: audit_ledger.py verify FILE [--head HASH]", file=sys.stderr)
            return 2
        del argv[i:i + 2]
    if len(argv) != 2 or argv[0] != "verify":
        print("usage: audit_ledger.py verify FILE [--head HASH]", file=sys.stderr)
        return 2
    try:
        ok, bad, reason = verify(argv[1], expected_head=head)
    except LedgerError as exc:
        print("MALFORMED: %s" % exc)
        return 2
    if ok:
        print("LEDGER OK: chain intact")
        return 0
    print("LEDGER TAMPERED at seq %s: %s" % (bad, reason))
    return 1


if __name__ == "__main__":
    sys.exit(main())
