// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Evidence, Finding } from "../api/types";
import { IconArrowRight, IconCheckCircle, IconFile } from "../components/Icons";
import { DataTable, type Column } from "../components/table";
import { AsyncView, Card, EmptyState, ErrorState, LoadingPage, PageHeader, Pill, SeverityBadge, TextList, Time } from "../components/ui";
import { agentKeyFor, agentName, loadScanContext, paths, type ScanContext } from "../lib/data";
import { formatLocation, shortCommit } from "../lib/format";
import { NO_AGENT_LINES, NO_AGENT_TITLE, SEVERITIES, severityLabel, severityRank, sourceTypeLabel, validityLabel } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import { StandardsList } from "./ControlDetail";

function scanCrumbs(ctx: ScanContext) {
  return [
    { label: "Overview", to: "/" },
    { label: ctx.project.name, to: paths.project(ctx.project.id) },
    { label: `Scan of ${ctx.detail.scan.target || "repository"}`, to: paths.scan(ctx.detail.scan.id) },
  ];
}

export function matchesText(f: Finding, needle: string): boolean {
  if (!needle) return true;
  const n = needle.toLowerCase();
  return [f.title, f.description, f.rule_id, f.control_id, f.why_it_matters, f.location?.path ?? ""].some((v) => v.toLowerCase().includes(n));
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

// --- List -------------------------------------------------------------------------

function FindingsTable({ ctx }: { ctx: ScanContext }) {
  const scanId = ctx.detail.scan.id;
  const res = ctx.detail.result;
  const [params, setParams] = useSearchParams();
  const severity = params.get("severity") ?? "";
  const control = params.get("control") ?? "";
  const agent = params.get("agent") ?? "";
  const [text, setText] = useState(params.get("q") ?? "");
  const q = useDebounced(text, 300);

  // Severity, control, and agent are filtered by the server. Text search runs here.
  const list = useAsync(
    (signal) => api.scanFindings(scanId, { severity, control_id: control, agent_id: agent }, signal),
    [scanId, severity, control, agent],
  );

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };
  useEffect(() => {
    if ((params.get("q") ?? "") !== q) set("q", q);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  const controlIds = useMemo(() => [...new Set((res.findings ?? []).map((f) => f.control_id))].sort(), [res.findings]);
  const agents = res.agents ?? [];
  const anyFilter = !!(severity || control || agent || q);

  const columns: Column<Finding>[] = [
    { key: "sev", label: "Severity", sort: (f) => severityRank(f.severity), render: (f) => <SeverityBadge severity={f.severity} /> },
    {
      key: "title",
      label: "Finding",
      rowHeader: true,
      sort: (f) => f.title,
      render: (f) => (
        <>
          <Link to={paths.finding(scanId, f.finding_id)}>{f.title}</Link>
          <span className="cell-sub mono">{f.rule_id}</span>
        </>
      ),
    },
    {
      key: "control",
      label: "Control",
      sort: (f) => f.control_id,
      render: (f) =>
        f.agent_id !== "*" ? (
          <Link to={paths.control(scanId, f.control_id, f.agent_id)} className="mono">
            {f.control_id}
          </Link>
        ) : (
          <span className="mono">{f.control_id}</span>
        ),
    },
    { key: "agent", label: "Agent", sort: (f) => agentName(agents, f.agent_id), render: (f) => agentName(agents, f.agent_id) },
    {
      key: "loc",
      label: "File and line",
      sort: (f) => formatLocation(f.location) || null,
      render: (f) => (f.location?.path ? <span className="mono wrap">{formatLocation(f.location)}</span> : <span className="muted">No file location</span>),
    },
  ];

  return (
    <Card flush>
      <div className="filters">
        <div className="field field-grow">
          <label htmlFor="f-q">Search findings</label>
          <input id="f-q" type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Title, rule, or file" />
        </div>
        <div className="field">
          <label htmlFor="f-sev">Severity</label>
          <select id="f-sev" value={severity} onChange={(e) => set("severity", e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {severityLabel(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-control">Control</label>
          <select id="f-control" value={control} onChange={(e) => set("control", e.target.value)}>
            <option value="">All controls</option>
            {controlIds.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-agent">Agent</label>
          <select id="f-agent" value={agent} onChange={(e) => set("agent", e.target.value)}>
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name || a.id}
              </option>
            ))}
          </select>
        </div>
        {anyFilter && (
          <button
            type="button"
            className="btn btn-small filters-clear"
            onClick={() => {
              setText("");
              setParams({}, { replace: true });
            }}
          >
            Clear filters
          </button>
        )}
      </div>
      <AsyncView state={list}>
        {(page) => {
          const rows = page.items.filter((f) => matchesText(f, q));
          return (
            <>
              <p className="filters-count" aria-live="polite" data-testid="findings-count">
                Showing {rows.length} of {(res.findings ?? []).length} findings
                {agent ? ". The agent filter also keeps repository-level findings, because they apply to every agent." : "."}
              </p>
              {(res.findings ?? []).length === 0 ? (
                <EmptyState title="This scan reported no findings" icon={<IconCheckCircle size={28} />}>
                  <p>No finding does not prove that every control works. Check the control statuses of each agent.</p>
                </EmptyState>
              ) : (
                <DataTable columns={columns} rows={rows} rowKey={(f) => f.finding_id} caption="Findings" initialSort={{ key: "sev", dir: "asc" }} empty="No finding matches these filters." />
              )}
            </>
          );
        }}
      </AsyncView>
    </Card>
  );
}

export function Findings() {
  const { scanId = "" } = useParams();
  const state = useAsync((signal) => loadScanContext(scanId, signal), [scanId]);
  if (state.status === "loading") return <LoadingPage label="Loading findings" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Findings" />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }
  const ctx = state.data;
  const s = ctx.detail.scan;
  return (
    <>
      <PageHeader
        title="Findings"
        crumbs={[...scanCrumbs(ctx), { label: "Findings" }]}
        lead={
          <>
            Concrete problems the scanner found in the scan of <strong>{s.target || "the repository"}</strong>, uploaded{" "}
            <Time value={s.received_at} /> (commit <span className="mono">{shortCommit(s.commit_sha)}</span>).
          </>
        }
      />
      {(ctx.detail.result.agents ?? []).length === 0 && (
        <Card title={NO_AGENT_TITLE}>
          <TextList items={NO_AGENT_LINES} />
        </Card>
      )}
      <FindingsTable ctx={ctx} />
    </>
  );
}

// --- Detail -------------------------------------------------------------------------

export function FindingDetail() {
  const { scanId = "", findingId = "" } = useParams();
  const state = useAsync((signal) => loadScanContext(scanId, signal), [scanId]);
  if (state.status === "loading") return <LoadingPage label="Loading the finding" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Finding" />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }
  const ctx = state.data;
  const res = ctx.detail.result;
  const f = (res.findings ?? []).find((x) => x.finding_id === findingId);
  const crumbs = [...scanCrumbs(ctx), { label: "Findings", to: paths.findings(scanId) }];
  if (!f) {
    return (
      <>
        <PageHeader title="Finding" crumbs={[...crumbs, { label: findingId }]} />
        <EmptyState title="This finding is not in this scan">
          <p>The finding may have been resolved, or the link points to a different scan.</p>
          <p>
            <Link to={paths.findings(scanId)} className="btn">
              All findings of this scan
            </Link>
          </p>
        </EmptyState>
      </>
    );
  }
  const key = f.agent_id === "*" ? undefined : agentKeyFor(ctx, f.agent_id);
  const controlAgent = f.agent_id === "*" ? (res.assessments?.[0]?.agent_id ?? "") : f.agent_id;
  const control = res.assessments?.find((a) => a.agent_id === controlAgent)?.controls?.find((c) => c.control_id === f.control_id);
  const evidence = (f.evidence_refs ?? [])
    .map((id) => (res.evidence ?? []).find((e) => e.evidence_id === id))
    .filter((e): e is Evidence => !!e);

  return (
    <>
      <PageHeader
        title={f.title}
        eyebrow={
          <span className="eyebrow-row">
            <SeverityBadge severity={f.severity} />
            <span>Finding</span>
            <span className="mono">{f.finding_id}</span>
          </span>
        }
        crumbs={[...crumbs, { label: f.finding_id }]}
      />

      <div className="grid-2-1">
        <div className="stack">
          <Card title="What was found">
            <p className="prose">{f.description}</p>
            {f.location?.path ? (
              <p className="file-loc" data-testid="finding-location">
                <IconFile size={18} />
                <span className="mono wrap">{formatLocation(f.location)}</span>
                {f.location.end_line && f.location.end_line !== f.location.line ? <span className="muted">to line {f.location.end_line}</span> : null}
              </p>
            ) : (
              <p className="muted">This finding has no file location.</p>
            )}
          </Card>

          <Card title="Why it matters" className="why-card">
            <p className="prose">{f.why_it_matters || "No explanation is recorded."}</p>
          </Card>

          <Card title="How to fix it" note="Follow the steps in order, then upload a new scan to confirm.">
            <TextList items={f.remediation} ordered empty="No remediation step is recorded." />
            {f.reproduction && (
              <>
                <h3 className="subhead">How to confirm the problem safely</h3>
                <p className="prose">{f.reproduction}</p>
              </>
            )}
          </Card>

          <Card title={`Evidence (${(f.evidence_refs ?? []).length})`}>
            {(f.evidence_refs ?? []).length === 0 ? (
              <p className="muted">This finding refers to no evidence item.</p>
            ) : (
              <ul className="evidence-refs">
                {(f.evidence_refs ?? []).map((id) => {
                  const e = evidence.find((x) => x.evidence_id === id);
                  return (
                    <li key={id}>
                      <span className="mono">{id}</span>
                      {e ? (
                        <>
                          <Pill>{sourceTypeLabel(e.source_type)}</Pill>
                          <Pill tone={e.validity === "valid" ? "neutral" : "warn"}>{validityLabel(e.validity)}</Pill>
                          <span className="evidence-ref-summary">{e.summary}</span>
                        </>
                      ) : (
                        <span className="muted">Not included in this scan file.</span>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card title="Details">
            <dl className="facts facts-1">
              <div>
                <dt>Severity</dt>
                <dd>
                  <SeverityBadge severity={f.severity} />
                </dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{f.confidence || "Not recorded"}</dd>
              </div>
              <div>
                <dt>Control</dt>
                <dd>
                  {controlAgent ? (
                    <Link to={paths.control(scanId, f.control_id, controlAgent)} className="link-arrow" data-testid="finding-control-link">
                      <span className="mono">{f.control_id}</span> {control?.title}
                      <IconArrowRight size={16} />
                    </Link>
                  ) : (
                    <span className="mono">{f.control_id}</span>
                  )}
                </dd>
              </div>
              <div>
                <dt>Agent</dt>
                <dd>{key ? <Link to={paths.agent(key)}>{agentName(res.agents, f.agent_id)}</Link> : agentName(res.agents, f.agent_id)}</dd>
              </div>
              <div>
                <dt>Rule</dt>
                <dd className="mono wrap">{f.rule_id}</dd>
              </div>
              <div>
                <dt>Seen in scan</dt>
                <dd>
                  <Link to={paths.scan(scanId)}>
                    <Time value={ctx.detail.scan.received_at} />
                  </Link>
                  <span className="fact-sub mono">{shortCommit(ctx.detail.scan.commit_sha)}</span>
                </dd>
              </div>
            </dl>
          </Card>
          <Card title="Standards references">
            <StandardsList mappings={f.mappings} />
          </Card>
        </div>
      </div>
    </>
  );
}
