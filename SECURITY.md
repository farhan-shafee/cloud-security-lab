# Security policy

This repository is a learning lab. It runs on sample data and doesn't operate a
production service, so the security concern here is narrow: not leaking anything
real through the example files.

## Reporting

If you spot a problem in the repo contents — an accidentally committed secret, a
sample that contains real data — open a private report through the repository's
security advisories, or contact the maintainer directly. Please don't open a
public issue for anything that looks like a live credential.

## Handling sample data

- No real credentials, account IDs, or customer data. The samples use the
  reserved documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`) and AWS's
  published example identifiers on purpose.
- If a real key is ever committed by mistake, rotate and revoke it first, then
  scrub the history.
