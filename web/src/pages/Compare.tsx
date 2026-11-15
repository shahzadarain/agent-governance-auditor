// SPDX-License-Identifier: Apache-2.0

import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { AgentDetail, AgentScan, CompareResponse, Finding, Project } from "../api/types";
import { IconArrowRight, IconCompare } from "../components/Icons";
import { AsyncView, Card, DecisionChip, EmptyState, ErrorState, LoadingPage, MaturityBar, Notice, PageHeader, SeverityBadge, StatusBadge } from "../components/ui";
import { controlTitle, paths } from "../lib/data";
import { absoluteTime, formatLocation, plural, shortCommit } from "../lib/format";
import { severityRank } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

interface Loaded {
  data: AgentDetail;
  project: Project;
  history: AgentScan[];
}

interface Diff {
  cmp: CompareResponse;
  newFindings: Finding[];
  resolved: Finding[];
  /** Findings of the newer scan that the older scan also had. */
  unchanged: Finding[];
  titles: Map<string, string>;
}

/** Keeps the findings of one agent plus repository-level findings. */
export function forAgent(findings: Finding[] | null | undefined, agentId: string): Finding[] {
  return (findings ?? [])
    .filter((f) => f.agent_id === agentId || f.agent_id === "*")
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title));
}

async function loadDiff(afterId: string, beforeId: string, agentId: string, signal: AbortSignal): Promise<Diff> {
  const [cmp, afterFindings, afterControls] = await Promise.all([
    api.compare(afterId, beforeId, signal),
    // The compare endpoint returns only a count of unchanged findings. The
    // list is the newer scan's findings minus the new ones.
    api.scanFindings(afterId, { agent_id: agentId }, signal),
    api.scanControls(afterId, { agent_id: agentId }, signal),
  ]);
  const newFindings = forAgent(cmp.comparison.new_findings, agentId);
  const newPrints = new Set((cmp.comparison.new_findings ?? []).map((f) => f.fingerprint));
  const seen = new Set<string>();
  const unchanged = forAgent(afterFindings.items, agentId).filter((f) => {
    if (newPrints.has(f.fingerprint) || seen.has(f.fingerprint)) return false;
    seen.add(f.fingerprint);
    return true;
  });
  return {
    cmp,
    newFindings,
    resolved: forAgent(cmp.comparison.resolved_findings, agentId),
    unchanged,
    titles: new Map(afterControls.items.map((c) => [c.control_id, c.title])),
  };
}

function scanLabel(s: AgentScan): string {
  return `${absoluteTime(s.received_at)} · ${s.profile} · ${s.score === null ? "no score" : `${s.score}/100`} · ${shortCommit(s.commit_sha)}`;
}

function FindingList({ items, scanId, empty }: { items: Finding[]; scanId: string; empty: string }) {
  if (items.length === 0) return <p className="muted">{empty}</p>;
  return (
    <ul className="finding-links">
      {items.map((f) => (
        <li key={f.finding_id}>
          <SeverityBadge severity={f.severity} />
          <Link to={paths.finding(scanId, f.finding_id)}>{f.title}</Link>
          <span className="mono muted wrap">
            {f.control_id}
            {f.location?.path ? ` · ${formatLocation(f.location)}` : ""}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ScanSide({ label, s }: { label: string; s: AgentScan }) {
  return (
    <div className="cmp-side">
      <p className="cmp-side-label">{label}</p>
      <p className="cmp-side-time" title={absoluteTime(s.received_at)}>
        {absoluteTime(s.received_at)}
      </p>
      <DecisionChip decision={s.decision} />
      <dl>
        <div>
          <dt>Commit</dt>
          <dd className="mono">{shortCommit(s.commit_sha)}</dd>
        </div>
        <div>
          <dt>Profile</dt>
          <dd>{s.profile}</dd>
        </div>
        <div>
          <dt>Policy</dt>
          <dd>
            {s.policy_pack} {s.policy_version}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function ScoreChange({ before, after }: { before: AgentScan; after: AgentScan }) {
  if (before.score === null || after.score === null) {
    return <p className="muted">At least one of the two scans has no score, so there is no score change to show.</p>;
  }
  const d = after.score - before.score;
  const tone = d > 0 ? "up" : d < 0 ? "down" : "flat";
  return (
    <div className={`score-change score-change-${tone}`} data-testid="score-change">
      <span className="score-change-nums">
        {before.score} <IconArrowRight size={20} /> {after.score}
      </span>
      <span className="score-change-delta">
        {d === 0 ? "No change" : `${d > 0 ? "Up" : "Down"} ${plural(Math.abs(d), "point")}`}
      </span>
      <span className="muted">Maturity score out of 100, illustrative only.</span>
    </div>
  );
}

function CompareBody({ loaded }: { loaded: Loaded }) {
  const { data, history } = loaded;
  const agent = data.agent;
  const [params, setParams] = useSearchParams();
  const sorted = [...history].sort((a, b) => Date.parse(b.received_at) - Date.parse(a.received_at));

  const after = sorted.find((s) => s.id === params.get("after")) ?? sorted[0];
  const older = after ? sorted.slice(sorted.indexOf(after) + 1) : [];
  const before = older.find((s) => s.id === params.get("before")) ?? older[0];

  const diff = useAsync<Diff | null>(
    (signal) => (after && before ? loadDiff(after.id, before.id, agent.agent_id, signal) : Promise.resolve(null)),
    [after?.id, before?.id, agent.agent_id],
  );

  if (sorted.length < 2 || !after) {
    return (
      <EmptyState title="A comparison needs two scans" icon={<IconCompare size={28} />}>
        <p>This agent appears in {plural(sorted.length, "scan")}. Upload another scan after you change the code or the evidence.</p>
        <p>
          <Link to={paths.agent(agent.key)} className="btn">
            Back to the agent
          </Link>
        </p>
      </EmptyState>
    );
  }

  return (
    <>
      <Card title="Choose two scans" note="The default is the latest scan against the one before it.">
        <div className="filters filters-plain">
          <div className="field field-grow">
            <label htmlFor="cmp-before">Older scan (before)</label>
            <select
              id="cmp-before"
              value={before?.id ?? ""}
              onChange={(e) => setParams({ after: after.id, before: e.target.value }, { replace: true })}
              disabled={older.length === 0}
            >
              {older.length === 0 && <option value="">No older scan</option>}
              {older.map((s) => (
                <option key={s.id} value={s.id}>
                  {scanLabel(s)}
                </option>
              ))}
            </select>
          </div>
          <div className="field field-grow">
            <label htmlFor="cmp-after">Newer scan (after)</label>
            <select id="cmp-after" value={after.id} onChange={(e) => setParams({ after: e.target.value }, { replace: true })}>
              {sorted.slice(0, -1).map((s) => (
                <option key={s.id} value={s.id}>
                  {scanLabel(s)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {!before ? (
        <Notice tone="info" title="The selected scan is the oldest one">
          Choose a newer scan on the right to compare.
        </Notice>
      ) : (
        <AsyncView state={diff}>
          {(d) => {
            if (!d) return null;
            const c = d.cmp.comparison;
            const changes = (c.control_changes ?? []).filter((x) => x.agent_id === agent.agent_id);
            return (
              <>
                <section className="cmp-head card" aria-label="Summary of the two scans">
                  <ScanSide label="Before" s={before} />
                  <div className="cmp-arrow" aria-hidden="true">
                    <IconArrowRight size={28} />
                  </div>
                  <ScanSide label="After" s={after} />
                  <div className="cmp-score">
                    <h2>Score change</h2>
                    {c.comparable ? (
                      <ScoreChange before={before} after={after} />
                    ) : (
                      <div data-testid="not-comparable">
                        <Notice tone="warn" title="Not comparable: policy changed">
                          The score change is hidden. The two scans used different rules ({c.not_comparable_why || "policy differs"}),
                          so a difference in score would not show real progress. The findings and control changes below are
                          still listed.
                        </Notice>
                      </div>
                    )}
                  </div>
                </section>

                <div className="cmp-counts" role="group" aria-label="Finding changes">
                  <div className="cmp-count cmp-new">
                    <span className="cmp-count-num">{d.newFindings.length}</span>
                    <span>New</span>
                  </div>
                  <div className="cmp-count cmp-resolved">
                    <span className="cmp-count-num">{d.resolved.length}</span>
                    <span>Resolved</span>
                  </div>
                  <div className="cmp-count cmp-same">
                    <span className="cmp-count-num">{d.unchanged.length}</span>
                    <span>Unchanged</span>
                  </div>
                  <div className="cmp-count cmp-controls">
                    <span className="cmp-count-num">{changes.length}</span>
                    <span>Controls changed</span>
                  </div>
                </div>

                <div className="grid-1-1">
                  <Card title={`New findings (${d.newFindings.length})`} note="In the newer scan only.">
                    <FindingList items={d.newFindings} scanId={after.id} empty="No new finding." />
                  </Card>
                  <Card title={`Resolved findings (${d.resolved.length})`} note="In the older scan only.">
                    <FindingList items={d.resolved} scanId={before.id} empty="No finding was resolved." />
                  </Card>
                </div>

                <Card title={`Control changes (${changes.length})`} note="Controls whose status or maturity differs between the two scans." flush>
                  {changes.length === 0 ? (
                    <p className="muted card-pad">No control changed status or maturity.</p>
                  ) : (
                    <div className="table-wrap" tabIndex={0} role="region" aria-label="Control changes">
                      <table className="table">
                        <thead>
                          <tr>
                            <th scope="col">Control</th>
                            <th scope="col">Before</th>
                            <th scope="col">After</th>
                            <th scope="col">Direction</th>
                          </tr>
                        </thead>
                        <tbody>
                          {changes.map((x) => {
                            const dir = x.after_maturity - x.before_maturity;
                            return (
                              <tr key={x.control_id}>
                                <th scope="row">
                                  <Link to={paths.control(after.id, x.control_id, agent.agent_id)}>
                                    <span className="mono">{x.control_id}</span> {d.titles.get(x.control_id) ?? controlTitle(undefined, x.control_id)}
                                  </Link>
                                </th>
                                <td>
                                  <StatusBadge status={x.before_status} /> <MaturityBar value={x.before_maturity} />
                                </td>
                                <td>
                                  <StatusBadge status={x.after_status} /> <MaturityBar value={x.after_maturity} />
                                </td>
                                <td>{dir > 0 ? "Improved" : dir < 0 ? "Regressed" : "Status changed"}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>

                <Card title={`Unchanged findings (${d.unchanged.length})`} note="Present in both scans.">
                  <FindingList items={d.unchanged} scanId={after.id} empty="No finding is present in both scans." />
                </Card>
              </>
            );
          }}
        </AsyncView>
      )}
    </>
  );
}

export function Compare() {
  const { agentKey = "" } = useParams();
  const state = useAsync<Loaded>(
    async (signal) => {
      const data = await api.agent(agentKey, signal);
      const [pd, history] = await Promise.all([api.project(data.agent.project_id, signal), api.agentScans(agentKey, signal)]);
      return { data, project: pd.project, history };
    },
    [agentKey],
  );
  if (state.status === "loading") return <LoadingPage label="Loading the comparison" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Compare scans" />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }
  const { data, project } = state.data;
  const name = data.agent.name || data.agent.agent_id;
  return (
    <>
      <PageHeader
        title="Compare scans"
        lead={
          <>
            What changed for <strong>{name}</strong> between two uploads: new, resolved, and unchanged findings, and
            controls that moved.
          </>
        }
        crumbs={[
          { label: "Overview", to: "/" },
          { label: project.name, to: paths.project(project.id) },
          { label: name, to: paths.agent(data.agent.key) },
          { label: "Compare scans" },
        ]}
      />
      <CompareBody loaded={state.data} />
    </>
  );
}
