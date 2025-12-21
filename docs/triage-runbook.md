# Triage runbook

Two alerts worked end to end. The goal isn't to memorize steps — it's to show the
shape of the decision: gather context, decide if the activity is authorized, and
either close it with a note or escalate with evidence.

## Alert A — Console login without MFA

Triggered by the detection in `detections/sigma/console-login-without-mfa.yml`.
Sample event: `examples/events/cloudtrail-consolelogin-no-mfa.json`.

**1. Pull context before judging.** From the event, note the principal
(`userIdentity.userName`), source IP, user agent, and time. In the sample that's
`analyst-user` from `198.51.100.24` at 14:31 UTC.

**2. Is the account meant to be exempt?** Some break-glass or service accounts
are intentionally MFA-exempt and *documented*. If this principal is on that list,
note it and close. If it isn't, keep going.

**3. Is the context normal for this user?** Compare the source IP and time
against where and when this user usually signs in. A 2am login from a new
geography is a very different finding from a 9am login from the office range.

**4. Look at what happened next.** Pull the same principal's API calls for the
15-30 minutes after the login. A no-MFA login followed by `CreatePolicyVersion`
or `ListBuckets` is a different story than one followed by nothing.

**5. Decide.**
- Authorized + normal context → close, and file the MFA gap as a hygiene finding
  (it's still F-001).
- Anything unexplained → contain: disable the session / rotate keys, then open an
  incident.

## Alert B — IAM policy version change

Triggered by `detections/sigma/iam-policy-version-change.yml`. The GuardDuty
sample (`examples/events/guardduty-credential-access.json`) is the kind of
finding that fires alongside this.

**1. Identify the actor and the target.** Who called `CreatePolicyVersion` /
`SetDefaultPolicyVersion`, and on which policy ARN.

**2. Diff the versions.** Compare the previous default against the new one. The
thing you're hunting for is privilege expansion — a new `Action: *`, a widened
`Resource`, or a fresh `iam:PassRole`. Running the new document through
`scripts/analyze_policy.py` gives you the same read offline.

**3. Was the change authorized?** Match it to a change ticket or an approved
window. An IAM write with no corresponding request is the finding.

**4. Decide.**
- Approved and scoped sensibly → close with the ticket reference.
- Unapproved, or approved but over-broad → roll back to the prior version, and if
  the actor may be compromised, rotate their credentials before anything else.

## When to escalate without finishing the runbook

Don't wait to complete every step if you see:

- A high-severity finding with no matching change window.
- Any concrete sign of credential compromise (impossible-travel, key used from a
  new ASN minutes after creation).
- Lateral-movement indicators, or repeated denied-auth anomalies on one principal.

Escalating early and being wrong costs a few minutes. The opposite costs the
account.
