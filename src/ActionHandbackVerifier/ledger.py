#!/usr/bin/env python3
"""Append-only hash-chain ledger for ActionHandbackVerifier verdicts (stdlib only).

Closed-audit loop: sample -> run --ledger -> append record -> verify --ledger.

Record shape:

    {
      "index": 0,
      "handback_id": "HB-VALID-001",
      "verdict": "valid",
      "aggregate_digest": "...",
      "result_hash": "...",
      "prev_hash": "",
      "record_hash": "..."
    }

Hash rules:
    - result_hash  = sha256 of canonical JSON of the full verdict result.
    - record_hash  = sha256 of canonical JSON of the record excluding record_hash.
    - Each next record stores the previous record's record_hash in prev_hash.

Canonical JSON: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
No wall-clock timestamps are stored, so records are deterministic.
"""

import hashlib
import json
import os

GENESIS_PREV_HASH = ""


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(value):
    return sha256_text(_canonical_json(value))


def result_hash(result):
    """Hash of the canonical JSON of the full verdict result."""
    return sha256_json(result)


def read_ledger(path):
    """Read all records from a JSONL ledger. Returns [] if the file is missing."""
    if not os.path.exists(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def last_record_hash(path):
    """Return the record_hash of the last record, or GENESIS_PREV_HASH if empty."""
    records = read_ledger(path)
    if not records:
        return GENESIS_PREV_HASH
    return records[-1].get("record_hash", "")


def append_record(path, result):
    """Append a deterministic hash-chain record for a verdict result.

    Returns the appended record dict.
    """
    records = read_ledger(path)
    index = len(records)
    prev_hash = records[-1].get("record_hash", "") if records else GENESIS_PREV_HASH
    record = {
        "index": index,
        "handback_id": result.get("handback_id", ""),
        "verdict": result.get("verdict", ""),
        "aggregate_digest": result.get("aggregate_digest", ""),
        "result_hash": result_hash(result),
        "prev_hash": prev_hash,
    }
    record["record_hash"] = sha256_json(record)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def verify_ledger(path):
    """Verify the append-only hash-chain integrity.

    Returns {"valid": bool, "records": int, "error": str}.
    An empty ledger is considered valid with zero records.
    """
    records = read_ledger(path)
    if not records:
        return {"valid": True, "records": 0, "error": ""}
    prev_hash = GENESIS_PREV_HASH
    for i, rec in enumerate(records):
        if rec.get("index") != i:
            return {
                "valid": False,
                "records": len(records),
                "error": f"record {i}: index mismatch (expected {i}, got {rec.get('index')})",
            }
        if rec.get("prev_hash") != prev_hash:
            return {
                "valid": False,
                "records": len(records),
                "error": f"record {i}: prev_hash mismatch (chain broken)",
            }
        stored = rec.get("record_hash")
        recomputed = sha256_json({k: v for k, v in rec.items() if k != "record_hash"})
        if stored != recomputed:
            return {
                "valid": False,
                "records": len(records),
                "error": f"record {i}: record_hash mismatch (tampered)",
            }
        prev_hash = stored
    return {"valid": True, "records": len(records), "error": ""}
