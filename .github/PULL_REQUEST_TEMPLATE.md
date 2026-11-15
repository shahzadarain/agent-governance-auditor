## What this changes

<!-- One or two sentences. Link the issue: "Fixes #123". -->

## Why

<!-- The problem this solves. -->

## How you tested it

<!-- Commands you ran and what you saw. Name your operating system. -->

## Checklist

- [ ] The pull request has one purpose and is as small as it can be.
- [ ] Tests are added or updated, and they fail without this change.
- [ ] `make check` passes (or `bash scripts/check-all.sh`, or `powershell -File scripts/check.ps1`).
- [ ] Fixtures and examples contain no real secrets, tokens, or private data.
- [ ] Documentation is updated for any change to behavior, flags, or output.
- [ ] `docs/IMPLEMENTATION_STATUS.md` states the honest status if detection or verification coverage changed.
- [ ] Commit subjects use the imperative mood and stay under 72 characters.

## For detector changes

<!-- Delete this section if it does not apply. -->

- [ ] Positive, negative, and malformed fixtures are included.
- [ ] No evidence has a strength above "implementation".
- [ ] No secret value appears in summaries, fingerprints, or logs.
- [ ] Known false positives and false negatives are described below.

## For control, profile, scoring, or decision changes

<!-- Delete this section if it does not apply. -->

- [ ] A design issue was discussed first: #
- [ ] Results that change for existing users are listed below.

## For dashboard changes

<!-- Delete this section if it does not apply. -->

- [ ] `npm run check` and `npm run build` ran in `web/`, and the updated `web/dist` is committed.

## Notes for the reviewer

<!-- Anything that needs attention: trade-offs, open questions, follow-up work. -->
