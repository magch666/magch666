#!/usr/bin/env python3
"""Analyze synthetic JSONL authentication events for a simple failure-burst pattern."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting a trailing Z for UTC."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def analyze_events(events: list[dict[str, Any]], threshold: int = 3) -> dict[str, Any]:
    """Summarize events and flag sources with repeated failures and later success."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    failures: Counter[str] = Counter()
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    successful = 0

    for event in events:
        required = {"timestamp", "source_ip", "username", "status"}
        missing = required - event.keys()
        if missing:
            raise ValueError(f"event missing required fields: {', '.join(sorted(missing))}")
        parse_timestamp(str(event["timestamp"]))
        if event["status"] not in {"success", "failure"}:
            raise ValueError("status must be 'success' or 'failure'")
        source = str(event["source_ip"])
        by_source[source].append(event)
        if event["status"] == "failure":
            failures[source] += 1
        else:
            successful += 1

    findings = []
    for source, source_events in sorted(by_source.items()):
        if failures[source] < threshold:
            continue
        ordered = sorted(source_events, key=lambda item: parse_timestamp(str(item["timestamp"])))
        threshold_event = next(
            event for index, event in enumerate(
                (item for item in ordered if item["status"] == "failure"), start=1
            ) if index == threshold
        )
        later_successes = [
            event for event in ordered
            if event["status"] == "success"
            and parse_timestamp(str(event["timestamp"]))
            > parse_timestamp(str(threshold_event["timestamp"]))
        ]
        findings.append({
            "type": "repeated_failures",
            "source_ip": source,
            "failed_attempts": failures[source],
            "threshold": threshold,
            "threshold_reached_at": threshold_event["timestamp"],
            "successful_login_after_threshold": bool(later_successes),
            "later_success_timestamps": [event["timestamp"] for event in later_successes],
            "severity": "review" if later_successes else "low",
        })

    return {
        "events_processed": len(events),
        "failed_attempts": sum(failures.values()),
        "successful_logins": successful,
        "sources_with_threshold_failures": len(findings),
        "findings": findings,
        "interpretation": (
            "Findings are triage leads, not proof of malicious activity."
        ),
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"line {line_number} must contain a JSON object")
            events.append(event)
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="JSON Lines input file")
    parser.add_argument("--output", type=Path, default=Path("report.json"))
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()

    try:
        report = analyze_events(read_jsonl(args.input), args.threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Events processed: {report['events_processed']}")
    print(f"Failed attempts: {report['failed_attempts']}")
    print(f"Successful logins: {report['successful_logins']}")
    print(f"Sources with {args.threshold}+ failures: {report['sources_with_threshold_failures']}")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
