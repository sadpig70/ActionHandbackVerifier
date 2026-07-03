![ActionHandbackVerifier](assets/ActionHandbackVerifier_hero.png)

# ActionHandbackVerifier

> Verify whether a delegated autonomous action was handed back with authority, custody, route, rollback, and public trace evidence intact.

## One-sentence pitch

`ActionHandbackVerifier` answers: *Can an autonomous agent prove that a delegated action was returned to the right authority without hiding private payloads or losing custody evidence?*

## Why this matters

Autonomous agents increasingly receive limited authority to act on behalf of a human, team, or system. The hard part is not only approving the action before it starts. The system also needs a deterministic handback check after the action finishes: who delegated it, what was returned, whether the route stayed inside policy, whether rollback was completed, and whether the trace is auditable without storing private payloads.

`ActionHandbackVerifier` is a stdlib-only CLI and Python package for that handback boundary.

## What it is not

- Not an identity provider.
- Not an authorization server.
- Not a live robot controller.
- Not a secret store or evidence archive.
- Not a legal liability engine.

It verifies a compact public handback packet and emits a deterministic verdict document.

## Install / Run

Requires Python 3.10+ and no external packages.

From this project root:

```bash
python -m pip install -e .
python -m ActionHandbackVerifier sample --out examples
python -m ActionHandbackVerifier run --input examples/valid.json
python -m ActionHandbackVerifier report --input examples/valid.json --out examples/valid.report.md
```

## Closed-audit ledger

`run --ledger PATH` appends a deterministic, append-only hash-chain record to a
`ledger.jsonl` file. `verify --ledger PATH` checks the chain integrity and detects
tampering. This turns the CLI into a closed audit loop:

```
sample -> run --ledger -> append record -> verify --ledger
```

```bash
# Append a verdict record (creates the ledger on first use, then chains)
python -m ActionHandbackVerifier run --input examples/valid.json --ledger examples/ledger.jsonl
python -m ActionHandbackVerifier run --input examples/thin.json --ledger examples/ledger.jsonl
python -m ActionHandbackVerifier run --input examples/breach.json --ledger examples/ledger.jsonl

# Verify the chain (exit code 0 = valid, 1 = tampered)
python -m ActionHandbackVerifier verify --ledger examples/ledger.jsonl
```

Each ledger record is one JSON line:

```json
{
  "index": 0,
  "handback_id": "HB-VALID-001",
  "verdict": "valid",
  "aggregate_digest": "...",
  "result_hash": "...",
  "prev_hash": "",
  "record_hash": "..."
}
```

Hash rules (canonical JSON: `sort_keys=True, separators=(",", ":")`, no timestamps):

- `result_hash` — sha256 of the canonical JSON of the full verdict result.
- `record_hash` — sha256 of the canonical JSON of the record excluding `record_hash`.
- Each next record stores the previous `record_hash` in `prev_hash` (the first record uses `""`).

`verify` returns:

```json
{ "valid": true, "records": 3, "error": "" }
```

## Packet format

A handback packet is JSON with these top-level sections:

- `handback_id` and `handback_time`
- `delegation` — authority id, delegated actor, action, allowed actions, expiry, evidence path.
- `custody` — artifact id, sender, receiver, confirmation, evidence path.
- `route` — planned route, actual route, route status, rollback requirement, evidence path.
- `rollback` — required/completed flags, restoration hash when applicable, evidence path.
- `trace` — public digest and evidence path.

Private payload fields such as `payload`, `private_payload`, `raw_payload`, `secret`, or `secrets` are rejected.

## Verdict scheme

- `valid` — all required predicates are satisfied.
- `thin` — the packet is not a confirmed breach, but evidence is incomplete or weak.
- `breach` — the handback violates authority, custody, rollback, trace, or evidence-path requirements.

The aggregate verdict is the highest severity across all checks.

## Python API

```python
from ActionHandbackVerifier import evaluate_handback

result = evaluate_handback(packet)
print(result["verdict"])
```

Ledger API:

```python
from ActionHandbackVerifier import append_record, verify_ledger

append_record("ledger.jsonl", result)
print(verify_ledger("ledger.jsonl"))  # {"valid": True, "records": 1, "error": ""}
```

## Tests

From this project root:

```bash
python -m unittest discover -s tests -q
```

## License

MIT License — see [LICENSE](LICENSE).
