# Investigation notes

## Question

Does the internal source `192.0.2.30` contacting four destination ports on `192.0.2.50` establish malicious scanning?

## Observed evidence

The synthetic flow file contains five connections from that source to that destination, with destination ports 22, 80, 443, 3389, and 445. Four distinct services is enough to cross the lab's default fan-out threshold. The script marks the pair for review.

## Assessment

The pattern is consistent with service discovery, but flow records alone do not establish intent. A systems administrator inventorying a server or a vulnerability scanner may generate a similar pattern. No payload, process, user, allow/deny outcome, or host role is included in this dataset.

## Next evidence to collect in an authorized environment

- Firewall allow/deny logs and the time window around the flows
- Asset owner and expected role of both endpoints
- Endpoint process and user context for the source
- Whether the activity repeats across additional hosts
- Approved change windows or scanner schedules

## Recommendation

Validate the source owner and operational context before escalation or blocking. Preserve the relevant telemetry and record which evidence supports the conclusion.

## Method limitations

The script counts unique destination ports per source/destination pair. It does not distinguish successful connections, infer service identity, or correlate time windows. Its output is a triage lead only.
