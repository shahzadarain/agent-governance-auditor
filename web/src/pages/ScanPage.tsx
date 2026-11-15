// SPDX-License-Identifier: Apache-2.0

import { Link, useParams } from "react-router-dom";
import { DecisionIcon, IconList, IconSearch } from "../components/Icons";
import { Card, DecisionChip, EmptyState, ErrorState, LoadingPage, Notice, PageHeader, TextList, Time } from "../components/ui";
import { agentKeyFor, loadScanContext, paths } from "../lib/data";
import { absoluteTime, plural } from "../lib/format";
import { decisionExplanation, decisionKey, decisionName, NO_AGENT_LINES, NO_AGENT_TITLE, orUnknown, profileSourceLabel } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

export function ScanPage() {
  const { scanId = "" } = useParams();
  const state = useAsync((signal) => loadScanContext(scanId, signal), [scanId]);
  if (state.status === "loading") return <LoadingPage label="Loading the scan" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Scan" />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }
  const ctx = state.data;
  const { scan, result } = ctx.detail;
  const agents = result.agents ?? [];
  const assessments = result.assessments ?? [];
  const warnings = result.warnings ?? [];
  const errorCount = assessments.reduce((n, a) => n + (a.controls ?? []).filter((c) => c.status === "error").length, 0);
  const outcome = decisionKey(scan.decision);
  const noAgent = agents.length === 0;

  return (
    <>
      <PageHeader
        title={`Scan of ${scan.target || "repository"}`}
        eyebrow={<span className="mono">{scan.scan_id}</span>}
        crumbs={[
          { label: "Overview", to: "/" },
          { label: ctx.project.name, to: paths.project(ctx.project.id) },
          { label: "Scans", to: paths.project(ctx.project.id, "scans") },
          { label: `Scan of ${scan.target || "repository"}` },
        ]}
        actions={
          <Link to={paths.findings(scan.id)} className="btn">
            <IconList size={16} />
            Findings ({(result.findings ?? []).length})
          </Link>
        }
      />

      {noAgent ? (
        <section className="banner banner-unknown" aria-labelledby="noagent-title">
          <div className="banner-icon" aria-hidden="true">
            <IconSearch size={36} />
          </div>
          <div className="banner-text">
            <p className="banner-kicker">Result</p>
            <h2 id="noagent-title">{NO_AGENT_TITLE}</h2>
            {NO_AGENT_LINES.map((l) => (
              <p key={l} className="banner-sentence">
                {l}
              </p>
            ))}
          </div>
        </section>
      ) : (
        <section className={`banner banner-${outcome}`} aria-labelledby="scan-decision">
          <div className="banner-icon" aria-hidden="true">
            <DecisionIcon decision={outcome} size={40} />
          </div>
          <div className="banner-text">
            <p className="banner-kicker">Repository decision: the most restrictive agent decision</p>
            <h2 id="scan-decision">{decisionName(scan.decision)}</h2>
            <p className="banner-sentence">{decisionExplanation(scan.decision)}</p>
          </div>
        </section>
      )}

      {(warnings.length > 0 || errorCount > 0) && (
        <Notice tone="warn" title="Parts of this scan did not complete">
          {errorCount > 0 && <p>{plural(errorCount, "control check")} ended with an error. An error is not a pass.</p>}
          {warnings.length > 0 && <TextList items={warnings} />}
        </Notice>
      )}

      <div className="grid-2-1">
        <Card title={`Agents in this scan (${agents.length})`} flush>
          {noAgent ? (
            <EmptyState title="No agent to show" icon={<IconSearch size={28} />}>
              <p>No control was assessed. This is not a pass.</p>
            </EmptyState>
          ) : (
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Agents in this scan">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Agent</th>
                    <th scope="col">Decision</th>
                    <th scope="col" className="num">
                      Score
                    </th>
                    <th scope="col">Owner</th>
                    <th scope="col">Framework</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((a) => {
                    const as = assessments.find((x) => x.agent_id === a.id);
                    const key = agentKeyFor(ctx, a.id);
                    return (
                      <tr key={a.id}>
                        <th scope="row">
                          {key ? <Link to={paths.agent(key)}>{a.name || a.id}</Link> : a.name || a.id}
                          <span className="cell-sub mono">{a.id}</span>
                        </th>
                        <td>{as ? <DecisionChip decision={as.decision.outcome} /> : <span className="muted">Not assessed</span>}</td>
                        <td className="num">{as?.score.value === null || !as ? <span className="muted">No score</span> : `${as.score.value}/100`}</td>
                        <td>{orUnknown(a.owner)}</td>
                        <td>{orUnknown(a.framework, "Unknown")}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Scan facts">
          <dl className="facts facts-1">
            <div>
              <dt>Uploaded</dt>
              <dd title={absoluteTime(scan.received_at)}>
                <Time value={scan.received_at} />
              </dd>
            </div>
            <div>
              <dt>Commit</dt>
              <dd className="mono wrap">{scan.commit_sha === "unknown" ? "Not readable" : scan.commit_sha}</dd>
            </div>
            <div>
              <dt>Profile</dt>
              <dd>
                {scan.profile}
                <span className="fact-sub">{profileSourceLabel(result.scan.profile_source)}</span>
              </dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>
                {scan.policy_pack} {scan.policy_version}
              </dd>
            </div>
            <div>
              <dt>Scanner</dt>
              <dd>
                {result.tool.name} {scan.tool_version}
                <span className="fact-sub">{result.scan.offline ? "Offline scan" : "Online scan"}</span>
              </dd>
            </div>
            <div>
              <dt>Files</dt>
              <dd>
                {result.stats.files_scanned} scanned, {result.stats.files_skipped} skipped
              </dd>
            </div>
          </dl>
        </Card>
      </div>

      <Card title="What this scan could not see" note="Limits that the scanner states for this scan.">
        <TextList items={result.limitations} empty="The scanner recorded no limitation." />
      </Card>
    </>
  );
}
