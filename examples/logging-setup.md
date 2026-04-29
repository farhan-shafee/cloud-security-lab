# Logging and Monitoring Setup (Example)

## Goals
- Capture management-plane API actions.
- Capture sign-in events and auth anomalies.
- Capture high-value security findings.

## Suggested Data Sources
- CloudTrail-style management events.
- GuardDuty-style threat findings.
- Identity provider sign-in events.

## Example Monitoring Use Cases
1. Console login without MFA.
2. Burst of IAM policy changes.
3. API calls from unusual geolocation/IP.
4. Discovery/recon command spikes.

## Basic Triage Flow
1. Validate event authenticity and timestamp.
2. Identify actor, source IP, user-agent, and action.
3. Check for related events in preceding/following 15 minutes.
4. Classify severity and escalate/remediate.
