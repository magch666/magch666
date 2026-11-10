# SOC Triage Lab: Authentication Log Analyzer

A small Python command-line tool for triaging authentication events in a **synthetic lab dataset**. It summarizes failed logins by source IP, highlights successful logins that follow repeated failures, and writes a concise JSON report for review.

This is a learning project. It is not a production SIEM, and the sample events do not describe a real incident.

## What it demonstrates

- Parsing structured authentication events
- Grouping failed logins by source address
- Detecting a simple failure-burst pattern
- Looking for a successful login after repeated failures
- Producing reviewable output while keeping detection logic explicit

## Requirements

- Python 3.10 or later
- No third-party packages

## Run

```bash
python3 src/analyze.py --input data/auth_events.jsonl --output report.json
```

Example output:

```text
Events processed: 14
Failed attempts: 8
Successful logins: 6
Sources with 3+ failures: 1
Success after 3+ failures: 1
Report written to report.json
```

The example is based on the included synthetic dataset. Thresholds are configurable with `--threshold`.

## Detection logic

1. Count failed authentication events by source IP.
2. Mark sources with at least the configured number of failures.
3. For each source, check whether a successful event occurs after its threshold-crossing failure.
4. Record findings with event timestamps and a severity label for analyst review.

A match is an investigative lead, not proof of malicious activity. NAT, shared networks, misconfigured clients, and legitimate users mistyping passwords can produce similar patterns.

## Scope and safety

All included events are synthetic. The tool reads local files and does not make network connections, attempt authentication, or interact with external systems. Use security tooling only on systems you own or have explicit authorization to assess.

## Limitations and next steps

- The parser expects JSON Lines with `timestamp`, `source_ip`, `username`, and `status` fields.
- This simple rule does not account for baselines, identity context, or event-time delays.
- A match should be reviewed with surrounding telemetry before taking action.

## License

MIT
