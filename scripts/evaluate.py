"""
SecuX Detection Evaluation — computes Precision, Recall, and F1 per detection
type and overall, given a labeled log dataset.

Dataset format  (JSON file, path passed as first argument):
{
  "entries": [
    {
      "raw":            "<34>Oct 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.1",
      "source":         "auth.log",           // used to pick the right parser
      "expected_types": ["brute_force_attempt"] // [] means benign — no detection expected
    },
    ...
  ]
}

Supported detection types (expected_types values):
  brute_force_attempt, off_hours_login, off_hours_activity, rapid_requests,
  error_rate_spike, privilege_escalation, malicious_process,
  suspicious_outbound_connection, data_exfiltration, log_gap,
  high_failure_ratio, sql_injection, xss, path_traversal,
  command_injection, brute_force, dos, reconnaissance,
  auth_bypass, malicious_execution, scanning

Usage:
  python scripts/evaluate.py datasets/my_labeled_logs.json
  python scripts/evaluate.py datasets/my_labeled_logs.json --verbose
"""

import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

# Make sure src/ is on the path when running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secux.Log_Analysis_Agent.parsers.autodetect import AutoDetectParser
from secux.Log_Analysis_Agent.parsers.base import LogEntry
from secux.Log_Analysis_Agent.analyzers.anomaly import AnomalyDetector, Anomaly


# ── helpers ───────────────────────────────────────────────────────────────────

def load_dataset(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    entries = data.get("entries", data) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError("Dataset must be a JSON object with an 'entries' list, or a bare list.")
    return entries


def raw_to_log_entry(raw: str, source: str) -> LogEntry:
    """
    Minimal parser: wraps a raw log line in a LogEntry so the detector can
    run on it.  The AutoDetectParser needs a filepath, so for labeled datasets
    that supply raw strings we build a synthetic LogEntry directly.
    We still attempt structured parsing via the syslog/IIS regexes.
    """
    parser = AutoDetectParser()
    import tempfile, os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=f"_{Path(source).name}", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(raw + "\n")
        tmp_path = tmp.name

    try:
        entries = list(parser.parse(tmp_path))
    finally:
        os.unlink(tmp_path)

    if entries:
        return entries[0]

    # Fallback: plain LogEntry with no structured fields
    return LogEntry(
        timestamp=datetime.now(timezone.utc),
        source=source or "unknown",
        event_type="unknown",
        level="Information",
        message=raw[:200],
        raw=raw[:500],
    )


def evaluate(dataset_path: str, verbose: bool = False):
    records = load_dataset(dataset_path)
    print(f"\nLoaded {len(records)} labeled records from {dataset_path}\n")

    # Per-type counters: {type: {tp, fp, fn}}
    counters: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    # Overall binary (attack vs benign)
    overall = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

    for i, record in enumerate(records):
        raw = record.get("raw", "")
        source = record.get("source", "unknown")
        expected: List[str] = [t.lower() for t in record.get("expected_types", [])]
        is_benign = len(expected) == 0

        # Build entry and run detector
        detector = AnomalyDetector()
        entry = raw_to_log_entry(raw, source)
        anomalies: List[Anomaly] = detector.analyze([entry])
        detected_types = {a.type.lower() for a in anomalies}

        if verbose:
            status = "BENIGN" if is_benign else f"ATTACK({','.join(expected)})"
            detected_str = ",".join(sorted(detected_types)) or "none"
            print(f"  [{i+1:4d}] expected={status:<35} detected={detected_str}")

        # ── per-type scoring ──────────────────────────────────────────────────
        for exp_type in expected:
            if exp_type in detected_types:
                counters[exp_type]["tp"] += 1
            else:
                counters[exp_type]["fn"] += 1

        for det_type in detected_types:
            if det_type not in expected:
                counters[det_type]["fp"] += 1

        # ── overall binary scoring ────────────────────────────────────────────
        any_detected = len(detected_types) > 0
        if is_benign:
            if any_detected:
                overall["fp"] += 1
            else:
                overall["tn"] += 1
        else:
            if any_detected:
                overall["tp"] += 1
            else:
                overall["fn"] += 1

    # ── print results ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  PER-TYPE RESULTS")
    print("=" * 70)
    print(f"  {'Type':<35} {'TP':>4} {'FP':>4} {'FN':>4}  {'Prec':>6} {'Rec':>6} {'F1':>6}")
    print("-" * 70)

    all_f1 = []
    for det_type in sorted(counters):
        c = counters[det_type]
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        all_f1.append(f1)
        print(f"  {det_type:<35} {tp:>4} {fp:>4} {fn:>4}  {prec:>5.1%} {rec:>5.1%} {f1:>5.1%}")

    print("=" * 70)

    # Overall binary
    tp, fp, fn, tn = overall["tp"], overall["fp"], overall["fn"], overall["tn"]
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    macro_f1 = sum(all_f1) / len(all_f1) if all_f1 else 0.0

    print(f"\n  OVERALL (attack vs benign)")
    print(f"  {'Metric':<20} {'Value':>8}")
    print(f"  {'-'*30}")
    print(f"  {'True Positives':<20} {tp:>8}")
    print(f"  {'False Positives':<20} {fp:>8}")
    print(f"  {'False Negatives':<20} {fn:>8}")
    print(f"  {'True Negatives':<20} {tn:>8}")
    print(f"  {'Precision':<20} {prec:>7.1%}")
    print(f"  {'Recall':<20} {rec:>7.1%}")
    print(f"  {'F1 Score':<20} {f1:>7.1%}")
    print(f"  {'Macro F1 (per-type)':<20} {macro_f1:>7.1%}")
    print("=" * 70 + "\n")

    return {
        "overall": {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)},
        "macro_f1": round(macro_f1, 4),
        "per_type": {
            t: {
                "tp": counters[t]["tp"],
                "fp": counters[t]["fp"],
                "fn": counters[t]["fn"],
            }
            for t in counters
        },
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate SecuX anomaly detection on a labeled log dataset."
    )
    parser.add_argument("dataset", help="Path to labeled JSON dataset file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print per-record expected vs detected")
    parser.add_argument("--out", "-o", default=None,
                        help="Write results to JSON file (optional)")
    args = parser.parse_args()

    results = evaluate(args.dataset, verbose=args.verbose)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Results written to {args.out}")


if __name__ == "__main__":
    main()
