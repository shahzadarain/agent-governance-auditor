# Governance

This document explains who makes decisions in AgentGov Auditor and how. The project is small and early-stage (alpha). The process is simple on purpose and will change as the community grows.

## Roles

### Maintainer

The project currently has one maintainer: Shahzad Asghar ([@shahzadarain](https://github.com/shahzadarain)), who is also the author.

The maintainer:

- reviews and merges pull requests;
- triages issues and security reports;
- makes releases;
- decides the roadmap, after listening to users;
- enforces the [Code of Conduct](CODE_OF_CONDUCT.md).

### Contributors

Anyone who opens an issue, sends a pull request, reviews a change, improves documentation, or reports a false positive is a contributor. Contributors do not need permission to take part.

### Users

People who run the tool. User reports shape priorities, even from users who never write code for the project.

## How decisions are made

- **Routine changes** (bug fixes, documentation, a detector improvement with tests): one maintainer approval on the pull request.
- **Larger changes** (new command, new dependency, new detector family, changes to output formats): discussed in an issue first. The maintainer decides after the discussion and records the reason in the issue.
- **Core changes** (controls, maturity levels, scoring, release decisions): an open design review, described below.

The maintainer looks for agreement first. When people disagree, the maintainer decides and explains why in public. Anyone can ask for a decision to be reconsidered by opening an issue with new information.

With a single maintainer, some maintainer changes merge without a second review. Those changes still go through pull requests and CI, so the history stays visible.

## Open review of controls and rules

The control catalog and the detectors define what the tool tells people about their agents. Changes to them happen in the open.

- Every change to a control, a profile, a scoring rule, or a detector goes through a public pull request. There are no private rule changes.
- A new control, a change in what a control means, or a change to scoring or decision logic needs a design issue first. The issue states what changes, why, and which results would differ. It includes at least one example with the result before and after.
- A design issue stays open for comment for at least seven days before a decision, unless it fixes a security problem or a clear error.
- Detectors follow the honesty rules in [docs/contributing-rules.md](docs/contributing-rules.md). A change that makes results look better without better evidence is rejected.
- Rule IDs and control IDs are stable. An ID is retired, never reused with a new meaning.
- Changes that alter results are listed in [CHANGELOG.md](CHANGELOG.md).
- Mappings to external frameworks are references for the reader. The project does not claim approval or endorsement from OWASP, NIST, or any other body.

## Becoming a maintainer

The project wants more maintainers. There is no fixed quota or time requirement. The maintainer invites a contributor when that person has shown, over a sustained period:

- several merged contributions of good quality, with tests;
- careful, constructive reviews of other people's work;
- sound judgment about honest reporting, with no pressure to overstate what the tool verifies;
- reliable, respectful conduct.

A contributor can also ask to be considered by opening an issue. A new maintainer gets write access and is listed in this file and in `.github/CODEOWNERS`.

A maintainer who is inactive for a long period, or who asks to step down, moves to emeritus status. Access is removed and can be restored later.

If the sole maintainer can no longer run the project, the intent is to hand it to an active contributor, and to state this in the README. The Apache-2.0 license lets anyone continue the work in a fork.

## Versioning

The project uses [Semantic Versioning](https://semver.org/).

- The current version is `0.1.0-dev`. No release has been tagged yet.
- While the version is `0.x`, breaking changes can happen in any minor release. The changelog lists them.
- Pre-release tags such as `-alpha.1` or `-beta.1` mark builds that are not stable.
- From `1.0.0`, breaking changes to the CLI or to documented formats need a new major version.

Three things are versioned separately from the CLI:

| Item | Where it appears | When it changes |
| --- | --- | --- |
| JSON result `schema_version` | In every JSON result | When the structure of the JSON result changes |
| Policy pack version | In every result as the policy version | When controls, profiles, or decision rules change |
| Rule IDs | In findings and SARIF | Never reused; retired when a rule is removed |

A new CLI version can ship with an unchanged schema version, and the reverse. Tools that read the JSON result should check `schema_version`. Results record the scanner version and the policy version so that a past decision can be traced.

## Release process

No release has been published yet. The planned process is:

1. All changes for the release are merged to `main`, and CI is green on Linux, macOS, and Windows.
2. The maintainer updates [CHANGELOG.md](CHANGELOG.md): moves entries from "Unreleased" to a new version section.
3. The maintainer verifies the README quick start by hand on a clean machine.
4. The maintainer pushes a version tag such as `v0.1.0`.
5. The release workflow (`.github/workflows/release.yml`) runs the tests, builds binaries for the supported platforms, writes checksums, attests build provenance, and creates the GitHub release. Tags with a pre-release suffix are marked as pre-releases.
6. The maintainer checks that the published binaries match the checksums and that the install instructions work.

Security fixes can be released outside the normal rhythm. See [SECURITY.md](SECURITY.md).

## Changes to this document

Changes to governance go through a public pull request, like any other change.
