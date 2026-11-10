# Network Traffic Investigation Lab

A defensive, offline lab for examining a small synthetic network flow dataset. A Python script summarizes conversations, highlights unusual port patterns, and produces a JSON report for analyst review.

All records are synthetic examples. The tool does not capture traffic or contact any host.

## Skills demonstrated

- Basic network flow interpretation
- Python data parsing and aggregation
- Hypothesis-driven triage and evidence-based reporting
- Clear discussion of false positives and limitations

## Requirements

Python 3.10+. No third-party packages.

## Run

```bash
python3 src/analyze_flows.py --input data/flows.csv --output report.json
```

To run the unit tests:

```bash
python3 -m unittest discover -s tests -v
```

## Lab question

One internal source contacts multiple destination ports on a single host. Is this enough to call it scanning? The report identifies the pattern as a lead; use the included analysis guide to explain what additional evidence would be needed.

## Dataset

The CSV uses documentation-only IP ranges and synthetic timestamps, byte counts, and ports. Fields are:

`timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,direction`

## Safety and scope

This project analyzes a local CSV file only. It performs no packet capture, probing, or network activity. Use real traffic only when you are authorized to access and analyze it.

## Limitations

Flow summaries do not contain payloads, endpoint identity, or full session state. A repeated-port pattern may come from legitimate applications, monitoring, or misconfiguration. Validate with network context before drawing conclusions.

See [docs/analysis.md](docs/analysis.md) for observations and a sample investigation write-up.
