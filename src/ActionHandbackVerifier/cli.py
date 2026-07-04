#!/usr/bin/env python3
"""CLI for ActionHandbackVerifier."""

import argparse
import json
import sys

from .ledger import append_record, verify_ledger
from .samples import write_samples
from .verifier import evaluate_handback, render_markdown


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dump_json(doc, path=None):
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def cmd_sample(args):
    written = write_samples(args.out)
    _dump_json({"written": written})
    return 0


def cmd_run(args):
    packet = _load_json(args.input)
    result = evaluate_handback(packet)
    _dump_json(result, args.out)
    if getattr(args, "ledger", None):
        append_record(args.ledger, result)
    if getattr(args, "fail_on_breach", False) and result["verdict"] == "breach":
        return 1
    if getattr(args, "strict", False) and result["verdict"] != "valid":
        return 1
    return 0 if result["verdict"] in {"valid", "thin", "breach"} else 1


def cmd_report(args):
    packet = _load_json(args.input)
    result = evaluate_handback(packet)
    text = render_markdown(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args):
    result = verify_ledger(args.ledger)
    _dump_json(result, args.out)
    return 0 if result["valid"] else 1


def build_parser():
    p = argparse.ArgumentParser(prog="ActionHandbackVerifier")
    sub = p.add_subparsers(dest="cmd", required=True)

    sample = sub.add_parser("sample", help="emit deterministic valid/thin/breach fixtures")
    sample.add_argument("--out", default="examples")
    sample.set_defaults(func=cmd_sample)

    run = sub.add_parser("run", help="evaluate one handback packet")
    run.add_argument("--input", required=True)
    run.add_argument("--out")
    run.add_argument("--ledger", help="append a hash-chain record to this ledger.jsonl path")
    run.add_argument("--strict", action="store_true", help="exit non-zero unless verdict is valid")
    run.add_argument("--fail-on-breach", action="store_true", help="exit non-zero when verdict is breach")
    run.set_defaults(func=cmd_run)

    report = sub.add_parser("report", help="render a Markdown report for one handback packet")
    report.add_argument("--input", required=True)
    report.add_argument("--out")
    report.set_defaults(func=cmd_report)

    verify = sub.add_parser("verify", help="verify an append-only ledger.jsonl hash chain")
    verify.add_argument("--ledger", required=True)
    verify.add_argument("--out")
    verify.set_defaults(func=cmd_verify)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)
