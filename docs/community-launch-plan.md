# Community launch plan: first 90 days

This is a proposed plan for the first 90 days after the first public release of AgentGov Auditor. It is a plan, not a record. Nothing on this page has happened yet.

## Principles

- **Trust first.** The project earns attention by being correct, honest about limits, and easy to try.
- **Measure, do not guess.** Every signal below is something to count. This page contains no current values, because none exist yet. Record real numbers as they arrive.
- **No invented numbers.** No star counts, download counts, user names, or testimonials that are not real and public.
- **No star-asking campaigns.** The project does not ask for stars, trade stars, or run giveaways.
- **No mass posting.** One relevant post in a community that allows it is better than ten copies in places that do not.
- **Follow each community's rules.** Read the posting rules before every post. If self-promotion is not permitted, do not post.
- **No implied endorsement.** The project is not sponsored, approved, or endorsed by OWASP or any other body. Posts say so plainly when the topic comes up.
- **One maintainer.** The plan has to fit the time one person has. When there is a conflict, fixing bugs comes before outreach.

## Pre-launch checklist

Complete every item before any public announcement.

### Product

- [ ] README quick start verified by hand on Windows, macOS, and Linux, each on a clean machine. Record the date and the operating system version for each.
- [ ] First tagged release published by the release workflow, with binaries and checksums.
- [ ] Checksums verified against the downloaded binaries on each operating system.
- [ ] Install instructions in the README match the release that exists.
- [ ] `agentgov scan` on the vulnerable example and the safe example gives the results the README shows.
- [ ] The GitHub Action runs from a second, separate repository, not only from this one.
- [ ] `docs/IMPLEMENTATION_STATUS.md` is current and lists known gaps.

### Documentation

- [ ] Screenshots are current and come from the real tool.
- [ ] Every command in the README was copied and run as written.
- [ ] FAQ, privacy page, and known limitations are published.
- [ ] GitLab and Azure DevOps examples are either verified or still labeled as illustrative.
- [ ] No page claims certification, endorsement, or adoption.

### Repository settings

- [ ] Private vulnerability reporting is enabled in the repository settings, so the route in `SECURITY.md` works. Test it by opening the form.
- [ ] Issue templates render correctly, and blank issues are disabled.
- [ ] Branch protection is on for `main`, with CI required.
- [ ] Discussions are enabled or not, as decided, and `SUPPORT.md` matches.
- [ ] Labels exist: `bug`, `false-positive`, `enhancement`, `detector`, `good first issue`, `help wanted`, `documentation`.
- [ ] Several real, well-described `good first issue` items are open.
- [ ] Repository description, topics, and social preview image are set.

### Measurement

- [ ] A simple tracking sheet exists for the signals below. Decide who updates it and how often.
- [ ] Baseline recorded on launch day for each signal. The baseline may be zero.

## Signals to track

Track these for all 90 days. Review them every two weeks. The "Target" column describes what to aim for; the maintainer sets numeric targets at launch, based on the launch-day baseline. No current values are stated here.

| Signal | How to measure | Target to set |
| --- | --- | --- |
| Successful installs reported | Count issues, discussions, and public posts where a person states that they installed and ran a scan. Count reports, not downloads. | A count per phase |
| Install failures reported | Count issues where install or the first scan failed, by operating system | Trend toward zero open failures |
| Quick start reproducibility | Run the README quick start on Windows, macOS, and Linux at each release. Record pass or fail for each. | Pass on all three, every release |
| Time to first response on issues | Median time from issue opened to first maintainer reply | A median in days |
| Time to close bugs | Median time from bug report to fix merged | A median in days |
| False-positive reports | Count of issues with the `false-positive` label | Count only; more reports early is healthy |
| Time to fix false positives | Median time from report to merged fix with a new fixture | A median in days |
| Share of wrong-result reports that became fixtures | Fixtures added divided by confirmed wrong-result reports | A percentage |
| External contributors | Number of people other than the maintainer with a merged pull request | A count per phase |
| First-time contributor experience | Median time from a first pull request opened to first review | A median in days |
| Documentation gaps closed | Count of merged documentation fixes that came from a user question or issue | A count per phase |
| Repeat questions | Number of questions asked more than once. Each one is a documentation gap. | Trend down |
| Security reports | Count of private reports and time to first acknowledgment | Acknowledge within the goal in `SECURITY.md` |
| CI integrations confirmed by users | Count of users who state that the Action or a CI example works for them, by platform | A count per phase |

Stars, forks, and download counts can be noted, but they are not goals. They say little about whether the tool helped anyone.

## Phase 1: days 1 to 30. Make the first scan work

**Goal:** a new user can install, scan, and understand the result without help.

### Activities

- Publish the first tagged release and the release notes.
- Announce once on the maintainer's own channels (GitHub profile, personal blog or professional network). Describe the problem, show real output, and state the limits: alpha, static analysis, not a certification.
- Watch issues daily. Reply to every new issue, even when the reply is only "seen, will look this week".
- Fix install and first-run problems before anything else.
- Add each confirmed wrong result as a fixture, with the fix.
- Turn each answered question into a documentation change.
- Ask a few people who build agents and are not security specialists to try the quick start, and watch where they get stuck. Record what they say, with permission.
- Keep `good first issue` items stocked and well described.

### Signals to review at day 30

- Successful installs reported, and install failures by operating system.
- Quick start reproducibility on three operating systems.
- Time to first response on issues.
- Number of false-positive reports, and time to fix.
- Documentation gaps closed.

### Decide at day 30

- Which install or first-run problems came up more than once? Fix or document them.
- Which detectors produced the most wrong results? Prioritize those.
- Is the response time sustainable for one maintainer? If not, say so publicly and adjust expectations in `SUPPORT.md`.

## Phase 2: days 31 to 60. Improve accuracy and welcome contributors

**Goal:** results get more accurate, and people outside the project start to contribute.

### Activities

- Publish a point release with the fixes from phase 1. List every change that alters results in the changelog.
- Write one or two practical articles on the maintainer's own channels. Good topics: what a static scan can and cannot prove about an agent, and how to move a control from "declared" to "implemented". Teach something useful even to readers who never install the tool.
- Share in relevant communities only where the rules permit it. Candidates include developer forums, DevSecOps groups, agent framework communities, and OWASP-related community channels. For each one:
  - read the rules first;
  - post once, in the right place, as an individual maintainer;
  - be clear that the project is independent and not endorsed by OWASP or anyone else;
  - stay to answer questions.
- Run the GitLab and Azure DevOps examples for real, or ask a user who has access to run them. Update the status lines to match what happened.
- Review pull requests from new contributors quickly. Thank contributors by name in the release notes.
- Label detector ideas from users as `detector` and `help wanted`, each with a positive and a negative example.
- Open design issues for any control or scoring change that user feedback suggests.

### Signals to review at day 60

- External contributors with a merged pull request.
- First-time contributor experience (time to first review).
- Time to fix false positives, and share of reports that became fixtures.
- CI integrations confirmed by users, by platform.
- Repeat questions.

### Decide at day 60

- Are contributors getting stuck in the same place? Fix the contributing guide.
- Which framework or language do users ask for most? Move it up in `ROADMAP.md`.
- Did any outreach break a community rule or draw complaints? Stop that channel.

## Phase 3: days 61 to 90. Build habits that last

**Goal:** the project keeps a steady rhythm that one maintainer, with help, can sustain.

### Activities

- Settle on a release rhythm the maintainer can keep, and state it in `GOVERNANCE.md`.
- Publish a compatibility matrix from real test runs only: operating systems, frameworks, CI platforms. Leave untested cells marked as untested.
- Publish a short, honest 90-day review: the measured signals, what went wrong, and what changes next. Include real numbers only.
- Update `ROADMAP.md` from what users asked for, with links to the issues.
- Invite regular contributors to review pull requests. Discuss the maintainer path in `GOVERNANCE.md` with anyone who shows sustained, careful work.
- If there is real demand, propose a talk or a written case study to a meetup or community group, following their submission process.
- Review `SECURITY.md` expectations against actual response times, and correct them if they were too optimistic.
- Close or relabel stale issues, with a clear explanation each time.

### Signals to review at day 90

- All signals, compared with the launch-day baseline and with days 30 and 60.
- Quick start reproducibility at the latest release.
- Open bug count and age of the oldest open bug.
- Number of people other than the maintainer who reviewed a pull request.

### Decide at day 90

- What is the single biggest reason a first scan fails or confuses? Make it the top priority.
- Is the false-positive rate going down? If not, slow new detectors and fix existing ones.
- Is there a candidate for a second maintainer?
- Which signals were not useful? Drop them. Which were missing? Add them.

## What this plan will not do

- Ask for stars, or count stars as success.
- Post the same announcement to many communities.
- Post where self-promotion is not allowed.
- Send unsolicited direct messages or emails about the project.
- Claim or imply that OWASP, NIST, or any other body sponsors, approves, or endorses the project.
- Publish benchmarks, adoption numbers, or compatibility claims that were not measured.
- Name a user or an organization without written permission.
- Describe the tool as a certification, or as a replacement for security review.

## Risks

| Risk | Response |
| --- | --- |
| More issues than one maintainer can answer | Say so openly, triage by impact, and ask for help with reproduction |
| Many false positives in early use | Treat them as the top priority, add fixtures, and slow new detectors |
| A user reads a pass as proof of safety | Keep the limits visible in the README, the reports, and the FAQ |
| A security report arrives during launch | Follow `SECURITY.md`; a security fix comes before all outreach |
| Quick start breaks on one operating system | Fix it or state it in the README the same day |
| Maintainer is unavailable for a period | Post a notice in the README and pin an issue |
