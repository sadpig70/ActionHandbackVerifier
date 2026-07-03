#!/usr/bin/env python3
"""Stdlib-only tests for the standalone ActionHandbackVerifier package."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
ENV = {**os.environ, "PYTHONPATH": SRC}

from ActionHandbackVerifier.samples import samples  # noqa: E402
from ActionHandbackVerifier.verifier import evaluate_handback, has_private_payload  # noqa: E402
from ActionHandbackVerifier.ledger import append_record, verify_ledger  # noqa: E402


class TestActionHandbackVerifierStandalone(unittest.TestCase):
    def test_sample_verdicts(self):
        docs = samples()
        self.assertEqual(evaluate_handback(docs["valid"])["verdict"], "valid")
        self.assertEqual(evaluate_handback(docs["thin"])["verdict"], "thin")
        self.assertEqual(evaluate_handback(docs["breach"])["verdict"], "breach")

    def test_deterministic_repeated_run(self):
        packet = samples()["valid"]
        self.assertEqual(evaluate_handback(packet), evaluate_handback(packet))

    def test_private_payload_is_rejected(self):
        packet = samples()["valid"]
        packet["private_payload"] = {"operator_note": "do not store"}
        self.assertTrue(has_private_payload(packet))
        self.assertEqual(evaluate_handback(packet)["verdict"], "breach")

    def test_cli_sample_run_report(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_output(
                [sys.executable, "-m", "ActionHandbackVerifier", "sample", "--out", d],
                cwd=ROOT,
                env=ENV,
                text=True,
            )
            valid = os.path.join(d, "valid.json")
            out = subprocess.check_output(
                [sys.executable, "-m", "ActionHandbackVerifier", "run", "--input", valid],
                cwd=ROOT,
                env=ENV,
                text=True,
            )
            self.assertEqual(json.loads(out)["verdict"], "valid")
            report = subprocess.check_output(
                [sys.executable, "-m", "ActionHandbackVerifier", "report", "--input", valid],
                cwd=ROOT,
                env=ENV,
                text=True,
            )
            self.assertIn("# ActionHandbackVerifier Report", report)
            self.assertIn("authority", report)


class TestLedger(unittest.TestCase):
    def test_append_after_run_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            for name in ("valid", "thin", "breach"):
                packet = samples()[name]
                result = evaluate_handback(packet)
                rec = append_record(ledger, result)
                self.assertEqual(rec["index"], {"valid": 0, "thin": 1, "breach": 2}[name])
                self.assertTrue(rec["record_hash"])
            result = verify_ledger(ledger)
            self.assertTrue(result["valid"])
            self.assertEqual(result["records"], 3)
            self.assertEqual(result["error"], "")

    def test_run_with_ledger_flag_appends(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_output(
                [sys.executable, "-m", "ActionHandbackVerifier", "sample", "--out", d],
                cwd=ROOT, env=ENV, text=True,
            )
            ledger = os.path.join(d, "ledger.jsonl")
            subprocess.check_output(
                [sys.executable, "-m", "ActionHandbackVerifier", "run",
                 "--input", os.path.join(d, "valid.json"), "--ledger", ledger],
                cwd=ROOT, env=ENV, text=True,
            )
            verify = json.loads(subprocess.check_output(
                [sys.executable, "-m", "ActionHandbackVerifier", "verify", "--ledger", ledger],
                cwd=ROOT, env=ENV, text=True,
            ))
            self.assertTrue(verify["valid"])
            self.assertEqual(verify["records"], 1)

    def test_tampered_ledger_detected(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            append_record(ledger, evaluate_handback(samples()["valid"]))
            append_record(ledger, evaluate_handback(samples()["thin"]))
            # tamper with the verdict of the second record (keeps JSON valid)
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[1])
            rec["verdict"] = "breach"
            lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertIn("record_hash mismatch", result["error"])

    def test_broken_chain_detected(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            append_record(ledger, evaluate_handback(samples()["valid"]))
            append_record(ledger, evaluate_handback(samples()["thin"]))
            # tamper with prev_hash of the second record
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[1])
            rec["prev_hash"] = "deadbeef" * 8
            lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertIn("prev_hash mismatch", result["error"])

    def test_cli_verify_returns_nonzero_on_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            append_record(ledger, evaluate_handback(samples()["valid"]))
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[0])
            rec["verdict"] = "thin"
            lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            proc = subprocess.run(
                [sys.executable, "-m", "ActionHandbackVerifier", "verify", "--ledger", ledger],
                cwd=ROOT, env=ENV, text=True, capture_output=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(json.loads(proc.stdout)["valid"])


if __name__ == "__main__":
    unittest.main()
