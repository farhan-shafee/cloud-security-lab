# Logging and monitoring setup

What has to be captured for the detections and the runbook to have anything to
work with. The detections are only as good as the data feeding them, so this is
upstream of everything in `detections/`.

## What to capture

- **Management-plane API calls** — the CloudTrail equivalent. This is the
  backbone; without it, the IAM and discovery detections have no input.
- **Sign-in events** — interactive console and federated logins, including the
  MFA flag. Feeds detection 1.
- **Threat findings** — the GuardDuty-style layer that does anomaly detection for
  you and emits findings like the one in `examples/events/`.

## Non-negotiables for the log pipeline

1. **Multi-region.** An attacker will operate in whatever region you're not
   logging. Trail coverage has to be all-region, not just `us-east-1`.
2. **Tamper-evidence.** Logs land somewhere the workload identities can't edit or
   delete — separate account or a write-once bucket. If the logs live where the
   attacker lands, they aren't evidence.
3. **Retention with a number on it.** "We keep logs" is not a control. Pick a
   retention period and enforce it.

## Monitoring use cases (where the detections come from)

1. Console login without MFA.
2. A burst of IAM policy changes.
3. API calls from an unusual geo / ASN.
4. Discovery / recon command spikes.

## The triage flow these feed

1. Validate the event is real and note its timestamp.
2. Identify the actor, source IP, user agent, and action.
3. Pull related events in the surrounding ~15 minutes.
4. Classify severity, then escalate or remediate.

That flow is worked in full in `docs/triage-runbook.md`.
