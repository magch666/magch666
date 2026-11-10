#!/usr/bin/env python3
"""Summarize offline synthetic network flows and flag broad port fan-out."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

FIELDS = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "direction"}


def analyze(rows, fanout_threshold=4):
    if fanout_threshold < 2:
        raise ValueError("fanout threshold must be at least 2")
    pairs = defaultdict(lambda: {"ports": set(), "flows": 0, "bytes": 0, "protocols": set()})
    for line, row in enumerate(rows, start=2):
        missing = FIELDS - row.keys()
        if missing:
            raise ValueError(f"row {line} missing fields: {', '.join(sorted(missing))}")
        try:
            dst_port, size = int(row["dst_port"]), int(row["bytes"])
            if not 0 <= dst_port <= 65535 or size < 0:
                raise ValueError
        except ValueError as exc:
            raise ValueError(f"row {line} has invalid dst_port or bytes") from exc
        key = (row["src_ip"], row["dst_ip"])
        pairs[key]["ports"].add(dst_port)
        pairs[key]["flows"] += 1
        pairs[key]["bytes"] += size
        pairs[key]["protocols"].add(row["protocol"].upper())

    summaries = []
    findings = []
    for (src, dst), values in sorted(pairs.items()):
        item = {
            "src_ip": src, "dst_ip": dst, "flows": values["flows"],
            "unique_destination_ports": len(values["ports"]),
            "destination_ports": sorted(values["ports"]),
            "bytes": values["bytes"], "protocols": sorted(values["protocols"]),
        }
        summaries.append(item)
        if len(values["ports"]) >= fanout_threshold:
            findings.append({
                "type": "destination_port_fanout",
                "source_ip": src, "destination_ip": dst,
                "unique_destination_ports": len(values["ports"]),
                "destination_ports": sorted(values["ports"]),
                "severity": "review",
                "interpretation": "Investigative lead; not proof of scanning or compromise.",
            })
    return {"flows_processed": sum(item["flows"] for item in summaries),
            "conversation_pairs": len(summaries), "summaries": summaries, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("report.json"))
    parser.add_argument("--fanout-threshold", type=int, default=4)
    args = parser.parse_args()
    try:
        with args.input.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        report = analyze(rows, args.fanout_threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(report, indent=2) + "\\n", encoding="utf-8")
    print(f"Flows processed: {report['flows_processed']}")
    print(f"Conversation pairs: {report['conversation_pairs']}")
    print(f"Port fan-out findings: {len(report['findings'])}")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
