// SPDX-License-Identifier: Apache-2.0

import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { AgentAssessment, AgentDetail as AgentDetailData, AgentScan, ControlResult, Project, ScanDetail } from "../api/types";
import { ScoreDial, ScoreHistory } from "../components/charts";
import { DecisionIcon, IconArrowRight, IconClock, IconCompare, IconList, IconWarning, RollupIcon } from "../components/Icons";
import { DataTable, type Column } from "../components/table";
import {
  Card,
  DecisionChip,
  ErrorState,
  LoadingPage,
  MandatoryMark,
  MaturityBar,
  Meter,
  Notice,
  PageHeader,
  Pill,
  SeverityBadge,
  StatusBadge,
  TextList,
  Time,
} from "../components/ui";
import { evidenceFor, findingsFor, groupByDomain, loadScan, paths, splitDomain } from "../lib/data";
import { absoluteTime, evidenceFreshness, plural, shortCommit } from "../lib/format";
import {
  decisionExplanation,
  decisionKey,
  decisionName,
  maturityName,
  orUnknown,
  profileSourceLabel,
  rollupLabel,
  rollupMeaning,
  rollupOf,
  ROLLUPS,
  SEVERITIES,
  statusLabel,
  type Rollup,
} from "../lib/labels";
import { useAsync } from "../lib/useAsync";

interface Loaded {
  data: AgentDetailData;
  project: Project;
  history: AgentScan[];
  scan: ScanDetail | null;
}

async function load(key: string, signal: AbortSignal): Promise<Loaded> {
  const data = await api.agent(key, signal);
  const [pd, history, scan] = await Promise.all([
    api.project(data.agent.project_id, signal),
    api.agentScans(key, signal),
    data.scan ? loadScan(data.scan.id).catch(() => null) : Promise.resolve(null),
  ]);
  return { data, project: pd.project, history, scan };
}

// --- Control grid -----------------------------------------------------------------

function ControlTile({ c, scanId }: { c: ControlResult; scanId: string }) {
  const r = rollupOf(c.status);
  const short = c.mandatory && c.applicable && c.maturity < c.min_maturity && c.status !== "not-applicable";
  return (
    <li>
      <Link to={paths.control(scanId, c.control_id, c.agent_id)} className={`tile tile-${r}${short ? " tile-short" : ""}`} data-testid="control-tile">
        <span className="tile-top">
          <span className="tile-id">{c.control_id}</span>
          {c.mandatory && <MandatoryMark min={c.min_maturity} />}
          {short && <span className="tile-flag">Below required level</span>}
        </span>
        <span className="tile-title">{c.title}</span>
        <span className={`tile-status status status-${r}`}>
          <RollupIcon rollup={r} size={16} />
          {statusLabel(c.status)}
        </span>
        <MaturityBar value={c.maturity} required={c.mandatory && c.applicable ? c.min_maturity : undefined} />
      </Link>
    </li>
  );
}

export function ControlGrid({ controls, scanId }: { controls: ControlResult[]; scanId: string }) {
  const groups = groupByDomain(controls);
  return (
    <div className="domains">
      {groups.map((g) => {
        const d = splitDomain(g.domain);
        return (
          <section key={g.domain} className="domain" aria-label={g.domain}>
            <h3>
              {d.letter && <span className="domain-letter">{d.letter}</span>}
              {d.name}
              <span className="domain-count">{plural(g.items.length, "control")}</span>
            </h3>
            <ul className="tiles">
              {g.items.map((c) => (
                <ControlTile key={c.control_id} c={c} scanId={scanId} />
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

function RollupLegend({ controls }: { controls: ControlResult[] }) {
  const counts: Record<Rollup, number> = { verified: 0, partial: 0, unknown: 0, failed: 0, na: 0 };
  for (const c of controls) counts[rollupOf(c.status)]++;
  return (
    <ul className="legend">
      {ROLLUPS.map((r) => (
        <li key={r} className={`status status-${r}`} title={rollupMeaning(r)}>
          <RollupIcon rollup={r} size={16} />
          <strong>{counts[r]}</strong> {rollupLabel(r)}
        </li>
      ))}
    </ul>
  );
}

// --- Blockers -----------------------------------------------------------------------

function Blockers({ a, scanId, profile }: { a: AgentAssessment; scanId: string; profile: string }) {
  const controls = a.controls ?? [];
  const unresolved = new Set(a.score.unresolved_mandatory ?? []);
  const reasons = a.decision.reasons ?? [];
  const blocking = controls.filter((c) => unresolved.has(c.control_id));
  const general = reasons.filter((r) => !r.control_id || !unresolved.has(r.control_id));
  const outcome = decisionKey(a.decision.outcome);

  if (blocking.length === 0 && outcome === "allow") {
    return (
      <Notice tone="success" title={`Nothing blocks release under the ${profile} profile`}>
        Every mandatory control meets its required maturity. Controls that are not mandatory can still be improved: see
        the grid below.
      </Notice>
    );
  }
  return (
    <>
      {blocking.length > 0 && (
        <ol className="blockers">
          {blocking.map((c) => {
            const why = reasons.find((r) => r.control_id === c.control_id)?.message;
            return (
              <li key={c.control_id} className="blocker">
                <div className="blocker-head">
                  <Link to={paths.control(scanId, c.control_id, c.agent_id)} className="blocker-title">
                    <span className="mono">{c.control_id}</span> {c.title}
                  </Link>
                  <StatusBadge status={c.status} />
                </div>
                <p className="blocker-why">{why ?? c.status_reason}</p>
                <p className="blocker-level">
                  <MaturityBar value={c.maturity} required={c.min_maturity} />
                  <span>
                    Level {c.maturity} now ({maturityName(c.maturity)}). Level {c.min_maturity} required.
                  </span>
                </p>
                {c.next_action && (
                  <p className="blocker-next">
                    <IconArrowRight size={16} />
                    <span>
                      <strong>Next action:</strong> {c.next_action}
                    </span>
                  </p>
                )}
              </li>
            );
          })}
        </ol>
      )}
      {general.length > 0 && (
        <>
          <h3 className="subhead">{blocking.length > 0 ? "Other reasons for this decision" : "Reasons for this decision"}</h3>
          <ul className="bullets">
            {general.map((r, i) => (
              <li key={`${r.code}-${i}`}>
                {r.message}{" "}
                {r.control_id && (
                  <Link to={paths.control(scanId, r.control_id, a.agent_id)} className="mono">
                    {r.control_id}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

// --- Page -----------------------------------------------------------------------------

function historyColumns(agentKey: string, latestId: string): Column<AgentScan>[] {
  return [
    {
      key: "received",
      label: "Uploaded",
      rowHeader: true,
      sort: (s) => Date.parse(s.received_at),
      render: (s) => (
        <Link to={paths.scan(s.id)} title={absoluteTime(s.received_at)}>
          <Time value={s.received_at} />
        </Link>
      ),
    },
    { key: "decision", label: "Decision", render: (s) => <DecisionChip decision={s.decision} /> },
    { key: "score", label: "Score", align: "right", sort: (s) => s.score, render: (s) => (s.score === null ? <span className="muted">No score</span> : `${s.score}/100`) },
    { key: "profile", label: "Profile", sort: (s) => s.profile, render: (s) => s.profile },
    { key: "policy", label: "Policy", render: (s) => `${s.policy_pack} ${s.policy_version}` },
    { key: "commit", label: "Commit", render: (s) => <span className="mono">{shortCommit(s.commit_sha)}</span> },
    {
      key: "cmp",
      label: "Compare",
      render: (s) =>
        s.id === latestId ? (
          <span className="muted">Latest</span>
        ) : (
          <Link to={paths.compare(agentKey, latestId, s.id)}>With latest</Link>
        ),
    },
  ];
}

export function AgentDetail() {
  const { agentKey = "" } = useParams();
  const state = useAsync((signal) => load(agentKey, signal), [agentKey]);

  if (state.status === "loading") return <LoadingPage label="Loading the agent" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Agent" crumbs={[{ label: "Overview", to: "/" }, { label: "Projects", to: "/projects" }, { label: "Agent" }]} />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }

  const { data, project, history, scan } = state.data;
  const { agent, assessment, detail } = data;
  const name = agent.name || agent.agent_id;
  const crumbs = [
    { label: "Overview", to: "/" },
    { label: "Projects", to: "/projects" },
    { label: project.name, to: paths.project(project.id) },
    { label: name },
  ];
  const latestId = data.scan?.id ?? "";
  const meta = scan?.result.scan;

  if (!data.scan || !assessment) {
    return (
      <>
        <PageHeader title={name} eyebrow="Agent" crumbs={crumbs} />
        <Notice tone="warn" title="No assessment is available for this agent">
          {data.scan
            ? "The latest scan that included this agent carried no assessment for it. This is not a pass. Run the scan again."
            : "The scan that last included this agent can no longer be read. This is not a pass. Upload a new scan."}
        </Notice>
      </>
    );
  }

  const outcome = decisionKey(assessment.decision.outcome);
  const controls = assessment.controls ?? [];
  const score = assessment.score;
  const evidence = evidenceFor(scan?.result.evidence, agent.agent_id);
  const fresh = evidenceFreshness(evidence);
  const findings = findingsFor(scan?.result.findings, agent.agent_id);
  const errorControls = controls.filter((c) => c.status === "error");
  const warnings = scan?.result.warnings ?? [];
  const sev = SEVERITIES.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }));
  const previous = [...history].sort((a, b) => Date.parse(b.received_at) - Date.parse(a.received_at)).find((h) => h.id !== latestId);

  return (
    <>
      <PageHeader
        title={name}
        eyebrow={
          name === agent.agent_id ? (
            "Agent"
          ) : (
            <>
              Agent · <span className="mono">{agent.agent_id}</span>
            </>
          )
        }
        crumbs={crumbs}
        actions={
          <>
            <Link to={paths.findings(latestId, { agent: agent.agent_id })} className="btn">
              <IconList size={16} />
              Findings ({findings.length})
            </Link>
            {previous && (
              <Link to={paths.compare(agent.key)} className="btn">
                <IconCompare size={16} />
                Compare scans
              </Link>
            )}
          </>
        }
      />

      <section className={`banner banner-${outcome}`} aria-labelledby="decision-title" data-testid="decision-banner">
        <div className="banner-icon" aria-hidden="true">
          <DecisionIcon decision={outcome} size={40} />
        </div>
        <div className="banner-text">
          <p className="banner-kicker">Release decision</p>
          <h2 id="decision-title">{decisionName(assessment.decision.outcome)}</h2>
          <p className="banner-sentence">{decisionExplanation(assessment.decision.outcome)}</p>
        </div>
        <dl className="banner-facts">
          <div>
            <dt>Profile</dt>
            <dd>
              {data.scan.profile}
              {meta && <span className="fact-sub">{profileSourceLabel(meta.profile_source)}</span>}
            </dd>
          </div>
          <div>
            <dt>Policy</dt>
            <dd>
              {data.scan.policy_pack} {data.scan.policy_version}
            </dd>
          </div>
          <div>
            <dt>Evaluated</dt>
            <dd>
              <Time value={data.scan.received_at} />
              <span className="fact-sub mono">{shortCommit(data.scan.commit_sha)}</span>
            </dd>
          </div>
        </dl>
      </section>

      {(errorControls.length > 0 || warnings.length > 0) && (
        <Notice tone="warn" title="Parts of this scan did not complete">
          {errorControls.length > 0 && (
            <p>
              {plural(errorControls.length, "control")} could not be checked because of an error:{" "}
              {errorControls.map((c) => c.control_id).join(", ")}. An error is not a pass.
            </p>
          )}
          {warnings.length > 0 && (
            <p>
              The scanner reported {plural(warnings.length, "warning")}. <Link to={paths.scan(latestId)}>See the scan details</Link>.
            </p>
          )}
        </Notice>
      )}

      <div className="grid-2-1">
        <Card title="What blocks release" note="Mandatory controls that do not meet the required maturity, with the next step for each.">
          <Blockers a={assessment} scanId={latestId} profile={data.scan.profile} />
        </Card>

        <Card title="Score and coverage" className="score-card">
          <ScoreDial value={score.value} />
          <p className="score-caveat">
            The score summarizes maturity. It does not decide the release: a high score never waives a mandatory control.
          </p>
          <Meter label="Coverage" percent={score.coverage_percent} hint={`${score.controls_with_evidence} of ${score.applicable_controls} applicable controls have evidence.`} />
          <Meter label="Tested" percent={score.tested_percent} hint="Applicable controls proven by a test result or better (level 3 or 4)." />
          <Meter label="Operational" percent={score.operational_percent} hint="Applicable controls proven by evidence from the running system (level 4)." />
        </Card>
      </div>

      <Card
        title="The 24 controls"
        note="Grouped by domain. Each tile shows the status, the maturity level out of 4, and whether the control is mandatory. Select a tile for the evidence."
        actions={<RollupLegend controls={controls} />}
        className="controls-card"
      >
        <ControlGrid controls={controls} scanId={latestId} />
      </Card>

      <div className="grid-1-1">
        <Card title="Evidence freshness" note="Evidence can expire. Expired evidence is not credited.">
          {!scan ? (
            <p className="muted">The evidence of this scan could not be loaded.</p>
          ) : evidence.length === 0 ? (
            <p className="muted">This scan holds no evidence items for this agent.</p>
          ) : (
            <>
              {fresh.expired > 0 && (
                <Notice tone="warn" title={`${plural(fresh.expired, "evidence item")} expired`}>
                  Expired evidence does not count toward any control. Collect it again and upload a new scan.
                </Notice>
              )}
              <dl className="facts facts-3">
                <div>
                  <dt>Valid items</dt>
                  <dd>
                    {fresh.valid} <span className="muted">of {fresh.total}</span>
                  </dd>
                </div>
                <div>
                  <dt>Expired</dt>
                  <dd className={fresh.expired > 0 ? "num-high" : ""}>{fresh.expired}</dd>
                </div>
                <div>
                  <dt>Not credited for other reasons</dt>
                  <dd className={fresh.otherInvalid > 0 ? "num-high" : ""}>{fresh.otherInvalid}</dd>
                </div>
              </dl>
              <p className="fresh-line">
                <IconClock size={18} />
                {fresh.nextExpiry ? (
                  <span>
                    The oldest valid-until date is <strong title={absoluteTime(fresh.nextExpiry)}>{fresh.nextExpiry.slice(0, 10)}</strong> (
                    <Time value={fresh.nextExpiry} />
                    ). {fresh.noExpiry > 0 ? `${plural(fresh.noExpiry, "valid item")} state no expiry.` : ""}
                  </span>
                ) : (
                  <span>No valid item states an expiry date. Scanner observations describe the scanned commit only.</span>
                )}
              </p>
            </>
          )}
        </Card>

        <Card
          title="Findings in this scan"
          actions={
            <Link to={paths.findings(latestId, { agent: agent.agent_id })} className="link-arrow">
              All findings
              <IconArrowRight size={16} />
            </Link>
          }
        >
          {findings.length === 0 ? (
            <p className="muted">The scan reported no finding for this agent. That alone does not prove a control works.</p>
          ) : (
            <ul className="sev-list">
              {sev.map(({ s, n }) => (
                <li key={s} className={n === 0 ? "zero" : ""}>
                  <SeverityBadge severity={s} />
                  <span className="sev-count">{n}</span>
                  {n > 0 && (
                    <Link to={paths.findings(latestId, { agent: agent.agent_id, severity: s })} aria-label={`Show ${s} findings`}>
                      Show
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Score history" note="One point per uploaded scan that included this agent. The score is illustrative only.">
        <ScoreHistory scans={history} />
        <DataTable columns={historyColumns(agent.key, latestId)} rows={history} rowKey={(s) => s.id} caption="Scan history of this agent" initialSort={{ key: "received", dir: "desc" }} />
      </Card>

      <Card title="About this agent" note="As reported by the latest scan. Unknown values stay unknown: the scanner does not guess.">
        <dl className="facts">
          <div>
            <dt>Owner</dt>
            <dd>{orUnknown(detail?.owner ?? agent.owner)}</dd>
          </div>
          <div>
            <dt>Risk tier</dt>
            <dd>
              {orUnknown(detail?.risk_tier ?? agent.risk_tier)}
              {detail && detail.inferred_risk_tier && detail.inferred_risk_tier !== "unknown" && (
                <span className="fact-sub">Suggested by detected capabilities: {detail.inferred_risk_tier}</span>
              )}
            </dd>
          </div>
          <div>
            <dt>Framework</dt>
            <dd>
              {orUnknown(detail?.framework ?? agent.framework, "Unknown")}
              {detail && detail.framework_version !== "unknown" && detail.framework_version ? ` ${detail.framework_version}` : ""}
            </dd>
          </div>
          <div>
            <dt>Language</dt>
            <dd>{orUnknown(detail?.language ?? agent.language, "Unknown")}</dd>
          </div>
          {detail && (
            <>
              <div>
                <dt>Entry point</dt>
                <dd className="mono wrap">{orUnknown(detail.entrypoint, "Unknown")}</dd>
              </div>
              <div>
                <dt>Detection</dt>
                <dd>
                  {detail.detection}, {detail.confidence} confidence
                </dd>
              </div>
            </>
          )}
          <div>
            <dt>First seen</dt>
            <dd>
              <Time value={agent.first_seen} />
            </dd>
          </div>
          <div>
            <dt>Last evaluated</dt>
            <dd>
              <Time value={agent.last_seen} />
            </dd>
          </div>
        </dl>
        {detail && (
          <>
            <h3 className="subhead">Capabilities</h3>
            {(detail.capabilities ?? []).length === 0 ? (
              <p className="muted">No capability was detected.</p>
            ) : (
              <p className="pill-row">
                {(detail.capabilities ?? []).map((c) => (
                  <Pill key={c}>{c}</Pill>
                ))}
              </p>
            )}
            <h3 className="subhead">Tools ({(detail.tools ?? []).length})</h3>
            {(detail.tools ?? []).length === 0 ? (
              <p className="muted">No tool was detected.</p>
            ) : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label="Tools of this agent">
                <table className="table table-compact">
                  <thead>
                    <tr>
                      <th scope="col">Tool</th>
                      <th scope="col">Kind</th>
                      <th scope="col">Sensitive</th>
                      <th scope="col">Declared</th>
                      <th scope="col">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(detail.tools ?? []).map((t, i) => (
                      <tr key={`${t.name}-${i}`}>
                        <th scope="row" className="mono">
                          {t.name}
                        </th>
                        <td>{t.kind}</td>
                        <td>
                          {t.sensitive ? (
                            <span className="status status-partial" title={t.sensitive_why}>
                              <IconWarning size={15} />
                              Yes{t.sensitive_why ? `: ${t.sensitive_why}` : ""}
                            </span>
                          ) : (
                            "No"
                          )}
                        </td>
                        <td>{t.declared ? "Yes" : "No"}</td>
                        <td className="mono wrap">
                          {t.location?.path}
                          {t.location?.line ? `:${t.location.line}` : ""}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
        {scan && (scan.result.limitations ?? []).length > 0 && (
          <>
            <h3 className="subhead">What this scan could not see</h3>
            <TextList items={scan.result.limitations} />
          </>
        )}
      </Card>
    </>
  );
}
