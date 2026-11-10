# Lab analysis

## Scenario

Review a small, synthetic set of authentication events and identify source addresses with repeated failures. Check whether any successful login followed the configured failure threshold.

## Observations

With the default threshold of three failures:

- 14 events are processed: 8 failures and 6 successes.
- Two sources cross the threshold: `192.0.2.10` and `192.0.2.13`.
- The sample source `192.0.2.10` has a success after its third failure.
- `192.0.2.13` reaches four failures and has no later success in this dataset.

These addresses are from the documentation-only ranges in RFC 5737 and are used as examples, not routable targets.

## Triage interpretation

The sequence from `192.0.2.10` merits contextual review because a successful login followed repeated failures. The events alone do not establish account compromise. An analyst would correlate identity, device, MFA, source network, and surrounding activity before deciding whether to contain or escalate.

The failures from `192.0.2.13` also warrant context, but the sample contains no later success. This could reflect user error, an automated client, or other benign behavior.

## Suggested defensive follow-up

- Confirm whether the account owner recognizes the activity.
- Review MFA outcomes, device history, and nearby authentication events.
- Check whether the source is shared through NAT or a known service.
- Apply existing lockout and alerting policies carefully; avoid blocking based on this rule alone.
- Preserve relevant logs and document the basis for any action.

## Limitations

This is a tiny synthetic dataset and a simple threshold rule. It does not model identity baselines, distributed attempts, event ingestion delays, or environment-specific policy. The report should be treated as a triage aid for a lab exercise, not an automated response decision.
