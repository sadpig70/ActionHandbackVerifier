#!/usr/bin/env python3
"""Deterministic sample packets for ActionHandbackVerifier."""

import copy
import json

from .verifier import digest_public_surface


VALID_PACKET = {
    "handback_id": "HB-VALID-001",
    "handback_time": "2026-07-02T00:00:00+00:00",
    "delegation": {
        "authority_id": "AUTH-17",
        "delegated_to": "field-agent-7",
        "return_to": "AUTH-17",
        "action": "retrieve_artifact",
        "allowed_actions": ["retrieve_artifact", "return_to_base"],
        "expires_at": "2026-07-03T00:00:00+00:00",
        "evidence_path": "evidence/delegation/AUTH-17.json"
    },
    "custody": {
        "artifact_id": "ART-42",
        "from_actor": "field-agent-7",
        "to_actor": "AUTH-17",
        "handback_confirmed": True,
        "evidence_path": "evidence/custody/ART-42.json"
    },
    "route": {
        "planned_route_id": "ROUTE-A",
        "actual_route_id": "ROUTE-A",
        "status": "passed",
        "rollback_required": False,
        "evidence_path": "evidence/route/ROUTE-A.json"
    },
    "rollback": {
        "required": False,
        "completed": False,
        "evidence_path": "evidence/rollback/not-required.json"
    },
    "trace": {
        "digest": "",
        "evidence_path": "evidence/trace/HB-VALID-001.sha256"
    }
}

THIN_PACKET = copy.deepcopy(VALID_PACKET)
THIN_PACKET["handback_id"] = "HB-THIN-001"
THIN_PACKET["route"]["status"] = "deviated"
THIN_PACKET["route"]["actual_route_id"] = "ROUTE-B"
THIN_PACKET["route"]["rollback_required"] = True
THIN_PACKET["rollback"]["required"] = True
THIN_PACKET["rollback"]["completed"] = True
THIN_PACKET["rollback"].pop("restoration_hash", None)

BREACH_PACKET = copy.deepcopy(VALID_PACKET)
BREACH_PACKET["handback_id"] = "HB-BREACH-001"
BREACH_PACKET["delegation"]["action"] = "open_restricted_zone"
BREACH_PACKET["custody"]["handback_confirmed"] = False
BREACH_PACKET["route"]["status"] = "passed"


def _bound(packet):
    packet = copy.deepcopy(packet)
    packet["trace"]["digest"] = digest_public_surface(packet, omit_trace_digest=True)
    return packet


VALID_PACKET = _bound(VALID_PACKET)
THIN_PACKET = _bound(THIN_PACKET)
BREACH_PACKET = _bound(BREACH_PACKET)


def samples():
    return {
        "valid": copy.deepcopy(VALID_PACKET),
        "thin": copy.deepcopy(THIN_PACKET),
        "breach": copy.deepcopy(BREACH_PACKET),
    }


def write_samples(out_dir):
    import os

    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for name, packet in samples().items():
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(packet, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        written[name] = path
    return written
