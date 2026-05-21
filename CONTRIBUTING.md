# Contributing

This is a personal learning lab, but suggestions and fixes are welcome — a
sharper detection, a more realistic sample event, a clearer write-up.

A few ground rules that keep it useful:

- **Keep it reproducible.** Anything added should run from a clean clone with no
  cloud account attached.
- **Sample data only.** No real credentials, account IDs, or customer data. Use
  the documentation IP ranges and AWS's published example identifiers, as the
  existing samples do.
- **Don't overclaim.** This is a lab, not production experience, and the docs say
  so. Keep it that way.
- **Document the why.** New artifacts should come with enough context that
  someone can tell what they're looking at and why it matters.

Before opening a PR, run:

```bash
make validate
```

CI runs the same check, plus byte-compiles the linter, so a green local run
should mean a green PR.
