#!/usr/bin/env python3
"""Deterministic delegated-action handback verifier (stdlib only)."""

import copy
import datetime as _dt
import hashlib
import json
import re

SEVERITY = {"valid": 0, "thin": 1, "breach": 2}
PRIVATE_KEYS = {"payload", "private_payload", "raw_payload", "secret", "secrets"}
EVIDENCE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _check(name, verdict, reason, evidence_path=""):
    return {
        "name": name,
        "verdict": verdict,
        "reason": reason,
        "evidence_path": evidence_path or "",
    }


def valid(name, evidence_path):
    return _check(name, "valid", "predicate satisfied", evidence_path)


def thin(name, reason, evidence_path=""):
    return _check(name, "thin", reason, evidence_path)


def breach(name, reason, evidence_path=""):
    return _check(name, "breach", reason, evidence_path)


def missing(required, obj):
    if not isinstance(obj, dict):
        return list(required)
    return [k for k in required if k not in obj or obj[k] in ("", None)]


def thin_or_breach(name, missing_fields):
    fields = ", ".join(missing_fields)
    if "evidence_path" in missing_fields:
        return breach(name, f"missing evidence path; also missing: {fields}")
    return thin(name, f"missing fields: {fields}")


def _parse_time(value):
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _dt.datetime.fromisoformat(text)
    except ValueError:
        return None


def expired(expires_at, handback_time):
    expires = _parse_time(expires_at)
    handback = _parse_time(handback_time)
    return bool(expires and handback and expires < handback)


def is_sha256_hex(value):
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))


def valid_evidence_path(value):
    text = str(value or "")
    if not text or text.startswith(("/", "\\")) or ".." in text.replace("\\", "/").split("/"):
        return False
    return bool(EVIDENCE_PATH_RE.fullmatch(text)) and text.replace("\\", "/").startswith("evidence/")


def has_private_payload(value):
    if isinstance(value, dict):
        for key, sub in value.items():
            if str(key).lower() in PRIVATE_KEYS:
                return True
            if has_private_payload(sub):
                return True
    elif isinstance(value, list):
        return any(has_private_payload(item) for item in value)
    return False


def _public_copy(value, omit_trace_digest=False, path=()):
    if isinstance(value, dict):
        return {
            k: _public_copy(v, omit_trace_digest, path + (str(k),))
            for k, v in sorted(value.items())
            if str(k).lower() not in PRIVATE_KEYS
            and not (omit_trace_digest and path == ("trace",) and str(k) == "digest")
        }
    if isinstance(value, list):
        return [_public_copy(v, omit_trace_digest, path) for v in value]
    return value


def digest_public_surface(packet, omit_trace_digest=False):
    public = _public_copy(packet, omit_trace_digest=omit_trace_digest)
    payload = json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def invalid_evidence_path_check(name, evidence_path):
    if not valid_evidence_path(evidence_path):
        return breach(name, "invalid evidence path", evidence_path)
    return None


def check_authority(packet):
    delegation = packet.get("delegation", {})
    miss = missing(["authority_id", "delegated_to", "action", "allowed_actions", "evidence_path"], delegation)
    if miss:
        return thin_or_breach("authority", miss)
    invalid = invalid_evidence_path_check("authority", delegation.get("evidence_path"))
    if invalid:
        return invalid
    if delegation["action"] not in delegation.get("allowed_actions", []):
        return breach("authority", "action outside delegated authority", delegation.get("evidence_path"))
    if expired(delegation.get("expires_at"), packet.get("handback_time")):
        return breach("authority", "delegation expired before handback", delegation.get("evidence_path"))
    return valid("authority", delegation.get("evidence_path"))


def check_custody(packet):
    custody = packet.get("custody", {})
    miss = missing(["artifact_id", "from_actor", "to_actor", "handback_confirmed", "evidence_path"], custody)
    if miss:
        return thin_or_breach("custody", miss)
    invalid = invalid_evidence_path_check("custody", custody.get("evidence_path"))
    if invalid:
        return invalid
    delegated_to = packet.get("delegation", {}).get("delegated_to")
    return_to = packet.get("delegation", {}).get("return_to", packet.get("delegation", {}).get("authority_id"))
    if delegated_to and custody.get("from_actor") != delegated_to:
        return breach("custody", "custody sender does not match delegated actor", custody.get("evidence_path"))
    if return_to and custody.get("to_actor") != return_to:
        return breach("custody", "custody receiver does not match return actor", custody.get("evidence_path"))
    if custody.get("handback_confirmed") is not True:
        return breach("custody", "handback not confirmed", custody.get("evidence_path"))
    return valid("custody", custody.get("evidence_path"))


def check_route(packet):
    route = packet.get("route", {})
    miss = missing(["planned_route_id", "actual_route_id", "status", "evidence_path"], route)
    if miss:
        return thin_or_breach("route", miss)
    invalid = invalid_evidence_path_check("route", route.get("evidence_path"))
    if invalid:
        return invalid
    status = route.get("status")
    if status == "failed":
        return breach("route", "route check failed", route.get("evidence_path"))
    if status == "passed" and route.get("planned_route_id") != route.get("actual_route_id"):
        return breach("route", "passed route has planned/actual mismatch", route.get("evidence_path"))
    if status == "deviated" and route.get("rollback_required") is not True:
        return thin("route", "route deviated but rollback requirement is not declared", route.get("evidence_path"))
    if status not in ("passed", "deviated"):
        return thin("route", f"unknown route status: {status}", route.get("evidence_path"))
    return valid("route", route.get("evidence_path"))


def check_rollback(packet):
    rollback = packet.get("rollback", {})
    miss = missing(["required", "completed", "evidence_path"], rollback)
    if miss:
        return thin_or_breach("rollback", miss)
    invalid = invalid_evidence_path_check("rollback", rollback.get("evidence_path"))
    if invalid:
        return invalid
    if rollback.get("required") is True and rollback.get("completed") is not True:
        return breach("rollback", "required rollback not completed", rollback.get("evidence_path"))
    if rollback.get("required") is True and not rollback.get("restoration_hash"):
        return thin("rollback", "rollback completed without restoration_hash", rollback.get("evidence_path"))
    if rollback.get("restoration_hash") and not is_sha256_hex(rollback.get("restoration_hash")):
        return breach("rollback", "restoration_hash is not sha256 hex", rollback.get("evidence_path"))
    return valid("rollback", rollback.get("evidence_path"))


def check_trace(packet):
    trace = packet.get("trace", {})
    if has_private_payload(packet):
        return breach("trace", "packet contains private payload field", trace.get("evidence_path", ""))
    if not trace.get("digest") or not trace.get("evidence_path"):
        return thin("trace", "trace digest or evidence_path missing", trace.get("evidence_path", ""))
    invalid = invalid_evidence_path_check("trace", trace.get("evidence_path"))
    if invalid:
        return invalid
    if not is_sha256_hex(trace.get("digest")):
        return breach("trace", "trace digest is not sha256 hex", trace.get("evidence_path"))
    expected = digest_public_surface(packet, omit_trace_digest=True)
    if trace.get("digest") != expected:
        return breach("trace", "trace digest does not bind public surface", trace.get("evidence_path"))
    return valid("trace", trace.get("evidence_path"))


def aggregate_verdict(checks):
    return max((c["verdict"] for c in checks), key=lambda v: SEVERITY[v])


def evaluate_handback(packet):
    """Evaluate one handback packet and return a deterministic verdict document."""
    packet = copy.deepcopy(packet)
    checks = [
        check_authority(packet),
        check_custody(packet),
        check_route(packet),
        check_rollback(packet),
        check_trace(packet),
    ]
    verdict = aggregate_verdict(checks)
    return {
        "handback_id": packet.get("handback_id", ""),
        "verdict": verdict,
        "checks": checks,
        "aggregate_digest": digest_public_surface(packet, omit_trace_digest=True),
    }


def render_markdown(result):
    lines = [
        f"# ActionHandbackVerifier Report — {result.get('handback_id', '')}",
        "",
        f"- verdict: {result['verdict']}",
        f"- aggregate_digest: `{result['aggregate_digest']}`",
        "",
        "## Checks",
        "",
        "| check | verdict | evidence_path | reason |",
        "|---|---|---|---|",
    ]
    for c in result["checks"]:
        lines.append(f"| {c['name']} | {c['verdict']} | `{c['evidence_path']}` | {c['reason']} |")
    lines.append("")
    return "\n".join(lines)
