// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Agent, ApiToken, CreatedToken, Member, ProjectDetail as ProjectDetailData, Scan } from "../api/types";
import { CreateTokenForm, errorText, TokenReveal } from "../components/forms";
import { IconPlug, IconSearch } from "../components/Icons";
import { DataTable, type Column } from "../components/table";
import {
  AsyncView,
  DecisionChip,
  EmptyState,
  ErrorState,
  Field,
  LoadingPage,
  Notice,
  PageHeader,
  Pill,
  Time,
} from "../components/ui";
import { loadScan, paths } from "../lib/data";
import { shortCommit } from "../lib/format";
import { decisionKey, decisionName, NO_AGENT_LINES, NO_AGENT_TITLE, projectRoleLabel } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import { countDecisions, DecisionBar, DecisionCountsRow } from "./Overview";

type Tab = "agents" | "scans" | "members" | "tokens";
const TABS: { key: Tab; label: string }[] = [
  { key: "agents", label: "Agents" },
  { key: "scans", label: "Scans" },
  { key: "members", label: "Members" },
  { key: "tokens", label: "Upload tokens" },
];

function canManage(role: string | undefined): boolean {
  return role === "administrator" || role === "owner";
}

// --- Agent inventory ------------------------------------------------------------

interface AgentRow extends Agent {
  /** Number of tools in the agent's latest scan; null when that scan could not be read. */
  tools: number | null;
}

async function loadInventory(projectId: string, signal: AbortSignal): Promise<AgentRow[]> {
  const agents = await api.projectAgents(projectId, signal);
  // The agent list does not carry a tool count. Read it from the latest scan
  // of each agent (usually one scan for the whole project).
  const scanIds = [...new Set(agents.map((a) => a.last_scan_id).filter(Boolean))].slice(0, 12);
  const scans = await Promise.all(scanIds.map((id) => loadScan(id).catch(() => null)));
  const tools = new Map<string, number>();
  scans.forEach((s) => {
    if (!s) return;
    for (const a of s.result.agents ?? []) tools.set(`${s.scan.id}|${a.id}`, a.tools?.length ?? 0);
  });
  return agents.map((a) => ({ ...a, tools: tools.get(`${a.last_scan_id}|${a.agent_id}`) ?? null }));
}

const agentColumns: Column<AgentRow>[] = [
  {
    key: "name",
    label: "Agent",
    rowHeader: true,
    sort: (a) => a.name || a.agent_id,
    render: (a) => (
      <>
        <Link to={paths.agent(a.key)}>{a.name || a.agent_id}</Link>
        <span className="cell-sub mono">{a.agent_id}</span>
      </>
    ),
  },
  {
    key: "decision",
    label: "Decision",
    sort: (a) => ["block", "review", "unknown", "allow"].indexOf(decisionKey(a.last_decision)),
    render: (a) => <DecisionChip decision={a.last_decision} />,
  },
  {
    key: "score",
    label: "Score",
    align: "right",
    sort: (a) => a.last_score,
    render: (a) => (a.last_score === null ? <span className="muted">No score</span> : <span className="score-cell">{a.last_score}<span className="muted">/100</span></span>),
  },
  { key: "owner", label: "Owner", sort: (a) => (a.owner === "unknown" ? null : a.owner), render: (a) => <Unknownable value={a.owner} /> },
  { key: "framework", label: "Framework", sort: (a) => a.framework, render: (a) => <Unknownable value={a.framework} what="Unknown" /> },
  { key: "language", label: "Language", sort: (a) => a.language, render: (a) => <Unknownable value={a.language} what="Unknown" /> },
  { key: "tier", label: "Risk tier", sort: (a) => (a.risk_tier === "unknown" ? null : a.risk_tier), render: (a) => <Unknownable value={a.risk_tier} /> },
  { key: "tools", label: "Tools", align: "right", sort: (a) => a.tools, render: (a) => (a.tools === null ? <span className="muted">–</span> : a.tools) },
  { key: "seen", label: "Last evaluated", sort: (a) => Date.parse(a.last_seen), render: (a) => <Time value={a.last_seen} /> },
];

function Unknownable({ value, what = "Not declared" }: { value: string; what?: string }) {
  return !value || value === "unknown" ? <span className="muted">{what}</span> : <>{value}</>;
}

function AgentInventory({ projectId, detail }: { projectId: string; detail: ProjectDetailData }) {
  const state = useAsync((signal) => loadInventory(projectId, signal), [projectId]);
  const [q, setQ] = useState("");
  const [decision, setDecision] = useState("");
  const rows = state.status === "ready" ? state.data : [];
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter(
      (a) =>
        (!decision || decisionKey(a.last_decision) === decision) &&
        (!needle ||
          [a.name, a.agent_id, a.owner, a.framework, a.language, a.risk_tier].some((v) => v.toLowerCase().includes(needle))),
    );
  }, [rows, q, decision]);

  if (detail.overview.scan_count === 0) {
    return (
      <EmptyState title="No scan has been uploaded yet" icon={<IconPlug size={28} />}>
        <p>Agents appear here after the first scan upload.</p>
        <p>
          <Link to={`/connect?project=${encodeURIComponent(projectId)}`} className="btn btn-primary">
            Connect a repository
          </Link>
        </p>
      </EmptyState>
    );
  }

  return (
    <AsyncView state={state}>
      {(all) =>
        all.length === 0 ? (
          <EmptyState title={NO_AGENT_TITLE} icon={<IconSearch size={28} />}>
            {NO_AGENT_LINES.map((l) => (
              <p key={l}>{l}</p>
            ))}
          </EmptyState>
        ) : (
          <>
            <div className="filters">
              <div className="field">
                <label htmlFor="agent-q">Search agents</label>
                <input id="agent-q" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name, owner, framework" />
              </div>
              <div className="field">
                <label htmlFor="agent-decision">Decision</label>
                <select id="agent-decision" value={decision} onChange={(e) => setDecision(e.target.value)}>
                  <option value="">All decisions</option>
                  <option value="block">{decisionName("BLOCK")}</option>
                  <option value="review">{decisionName("REVIEW_REQUIRED")}</option>
                  <option value="allow">{decisionName("ALLOW")}</option>
                </select>
              </div>
              <p className="filters-count" aria-live="polite">
                Showing {filtered.length} of {all.length}
              </p>
            </div>
            <DataTable
              columns={agentColumns}
              rows={filtered}
              rowKey={(a) => a.key}
              caption="Agent inventory"
              initialSort={{ key: "decision", dir: "asc" }}
              empty="No agent matches these filters."
            />
          </>
        )
      }
    </AsyncView>
  );
}

// --- Scans ----------------------------------------------------------------------

const scanColumns: Column<Scan>[] = [
  {
    key: "received",
    label: "Uploaded",
    rowHeader: true,
    sort: (s) => Date.parse(s.received_at),
    render: (s) => (
      <Link to={paths.scan(s.id)}>
        <Time value={s.received_at} />
      </Link>
    ),
  },
  { key: "target", label: "Target", sort: (s) => s.target, render: (s) => s.target },
  { key: "decision", label: "Decision", sort: (s) => s.decision, render: (s) => <DecisionChip decision={s.decision} /> },
  { key: "score", label: "Score", align: "right", sort: (s) => s.score, render: (s) => (s.score === null ? <span className="muted">No score</span> : `${s.score}/100`) },
  { key: "profile", label: "Profile", sort: (s) => s.profile, render: (s) => s.profile },
  { key: "policy", label: "Policy", render: (s) => `${s.policy_pack} ${s.policy_version}` },
  { key: "commit", label: "Commit", render: (s) => <span className="mono">{shortCommit(s.commit_sha)}</span> },
];

// --- Members ----------------------------------------------------------------------

function Members({ projectId }: { projectId: string }) {
  const state = useAsync((signal) => api.members(projectId, signal), [projectId]);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("viewer");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "danger" | "success"; text: string } | null>(null);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const m = await api.setMember(projectId, username.trim(), role);
      setMsg({ tone: "success", text: `${m.username} is now ${projectRoleLabel(m.role).toLowerCase()} of this project.` });
      setUsername("");
      state.reload(true);
    } catch (err) {
      setMsg({ tone: "danger", text: errorText(err) });
    } finally {
      setBusy(false);
    }
  };
  const remove = async (m: Member) => {
    setMsg(null);
    try {
      await api.removeMember(projectId, m.user_id);
      setMsg({ tone: "success", text: `${m.username} was removed from this project.` });
      state.reload(true);
    } catch (err) {
      setMsg({ tone: "danger", text: errorText(err) });
    }
  };

  const columns: Column<Member>[] = [
    { key: "user", label: "User", rowHeader: true, sort: (m) => m.username, render: (m) => m.username },
    { key: "role", label: "Role in this project", sort: (m) => m.role, render: (m) => <Pill>{projectRoleLabel(m.role)}</Pill> },
    {
      key: "act",
      label: "Action",
      render: (m) => (
        <button type="button" className="btn btn-small btn-danger" onClick={() => void remove(m)} aria-label={`Remove ${m.username}`}>
          Remove
        </button>
      ),
    },
  ];

  return (
    <>
      <p className="tab-intro">
        Owners manage tokens and members. Reviewers read everything and see audit events. Viewers read everything except
        audit events. Administrators have full access to every project and are not listed here.
      </p>
      <AsyncView state={state}>
        {(members) => (
          <DataTable columns={columns} rows={members} rowKey={(m) => m.user_id} caption="Project members" empty="This project has no members yet. Administrators can still see it." />
        )}
      </AsyncView>
      <h3 className="subhead">Add or change a member</h3>
      <form className="form-inline" onSubmit={add} aria-label="Add or change a member">
        <Field label="Username" hint="The user must already have an account on this server.">
          {({ id, describedBy }) => (
            <input id={id} value={username} onChange={(e) => setUsername(e.target.value)} aria-describedby={describedBy} required autoCapitalize="none" spellCheck={false} />
          )}
        </Field>
        <Field label="Role">
          {({ id }) => (
            <select id={id} value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="viewer">Viewer</option>
              <option value="reviewer">Reviewer</option>
              <option value="owner">Owner</option>
            </select>
          )}
        </Field>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Saving…" : "Save member"}
          </button>
        </div>
      </form>
      <div aria-live="polite">{msg && <Notice tone={msg.tone}>{msg.text}</Notice>}</div>
    </>
  );
}

// --- Tokens -----------------------------------------------------------------------

function tokenState(t: ApiToken): { label: string; tone: "neutral" | "warn" } {
  if (t.revoked_at) return { label: "Revoked", tone: "warn" };
  if (t.expires_at && Date.parse(t.expires_at) <= Date.now()) return { label: "Expired", tone: "warn" };
  return { label: "Active", tone: "neutral" };
}

function Tokens({ projectId }: { projectId: string }) {
  const state = useAsync((signal) => api.tokens(projectId, signal), [projectId]);
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [error, setError] = useState("");

  const revoke = async (t: ApiToken) => {
    setError("");
    try {
      await api.revokeToken(projectId, t.id);
      setConfirm(null);
      state.reload(true);
    } catch (err) {
      setError(errorText(err));
    }
  };

  const columns: Column<ApiToken>[] = [
    {
      key: "name",
      label: "Token",
      rowHeader: true,
      sort: (t) => t.name,
      render: (t) => (
        <>
          {t.name}
          <span className="cell-sub mono">agt_{t.prefix}_…</span>
        </>
      ),
    },
    { key: "state", label: "State", sort: (t) => tokenState(t).label, render: (t) => <Pill tone={tokenState(t).tone}>{tokenState(t).label}</Pill> },
    { key: "created", label: "Created", sort: (t) => Date.parse(t.created_at), render: (t) => <Time value={t.created_at} /> },
    { key: "used", label: "Last used", sort: (t) => (t.last_used_at ? Date.parse(t.last_used_at) : null), render: (t) => <Time value={t.last_used_at} fallback="Never" /> },
    { key: "expires", label: "Expires", sort: (t) => (t.expires_at ? Date.parse(t.expires_at) : null), render: (t) => <Time value={t.expires_at} fallback="No expiry" /> },
    {
      key: "act",
      label: "Action",
      render: (t) =>
        t.revoked_at ? (
          <span className="muted">
            Revoked <Time value={t.revoked_at} />
          </span>
        ) : confirm === t.id ? (
          <span className="confirm">
            <button type="button" className="btn btn-small btn-danger" onClick={() => void revoke(t)}>
              Revoke “{t.name}” now
            </button>
            <button type="button" className="btn btn-small" onClick={() => setConfirm(null)}>
              Keep
            </button>
          </span>
        ) : (
          <button type="button" className="btn btn-small" onClick={() => setConfirm(t.id)} aria-label={`Revoke token ${t.name}`}>
            Revoke
          </button>
        ),
    },
  ];

  return (
    <>
      <p className="tab-intro">
        An upload token lets the scanner send results to this project. It cannot read data. The server stores only a
        hash of each token.
      </p>
      {created && (
        <TokenReveal created={created} onDismiss={() => setCreated(null)} />
      )}
      <AsyncView state={state}>
        {(tokens) => <DataTable columns={columns} rows={tokens} rowKey={(t) => t.id} caption="Upload tokens" initialSort={{ key: "created", dir: "desc" }} empty="No token exists yet. Create one below." />}
      </AsyncView>
      <div aria-live="polite">{error && <Notice tone="danger">{error}</Notice>}</div>
      <h3 className="subhead">Create a token</h3>
      <CreateTokenForm
        projectId={projectId}
        onCreated={(t) => {
          setCreated(t);
          state.reload(true);
        }}
      />
    </>
  );
}

// --- Page ---------------------------------------------------------------------------

export function ProjectDetail() {
  const { projectId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = (TABS.find((t) => t.key === params.get("tab"))?.key ?? "agents") as Tab;
  const state = useAsync((signal) => api.project(projectId, signal), [projectId]);

  if (state.status === "loading") return <LoadingPage label="Loading the project" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Project" crumbs={[{ label: "Overview", to: "/" }, { label: "Projects", to: "/projects" }, { label: "Project" }]} />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }
  const selectTab = (key: Tab) => setParams(key === "agents" ? {} : { tab: key }, { replace: true });
  const d = state.data;
  const role = d.project.role;
  const counts = countDecisions(d.overview.decisions);
  const manage = canManage(role);

  return (
    <>
      <PageHeader
        title={d.project.name}
        eyebrow={<span className="mono">{d.project.slug}</span>}
        crumbs={[{ label: "Overview", to: "/" }, { label: "Projects", to: "/projects" }, { label: d.project.name }]}
        lead={
          <>
            Your role: <strong>{projectRoleLabel(role)}</strong>. {d.overview.agent_count === 1 ? "1 agent" : `${d.overview.agent_count} agents`},{" "}
            {d.overview.scan_count === 1 ? "1 scan" : `${d.overview.scan_count} scans`}.
          </>
        }
        actions={
          <>
            {d.overview.latest_scan_id && (
              <Link to={paths.findings(d.overview.latest_scan_id)} className="btn">
                Findings of the latest scan
              </Link>
            )}
            <Link to={`/connect?project=${encodeURIComponent(d.project.id)}`} className="btn">
              <IconPlug size={16} />
              Upload a scan
            </Link>
          </>
        }
      />

      {d.overview.scan_count > 0 && d.overview.agent_count > 0 && (
        <div className="summary-band">
          <div className="summary-main">
            <DecisionBar counts={counts} />
            <DecisionCountsRow counts={counts} />
          </div>
          <dl className="summary-facts">
            <div>
              <dt>Open critical</dt>
              <dd className={d.overview.open_critical > 0 ? "num-critical" : ""}>{d.overview.open_critical}</dd>
            </div>
            <div>
              <dt>Open high</dt>
              <dd className={d.overview.open_high > 0 ? "num-high" : ""}>{d.overview.open_high}</dd>
            </div>
            <div>
              <dt>Latest scan</dt>
              <dd className="summary-time">
                <Time value={d.overview.latest_scan_at} />
              </dd>
            </div>
          </dl>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Project sections">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            id={`tab-${t.key}`}
            aria-selected={tab === t.key}
            aria-controls="tab-panel"
            tabIndex={tab === t.key ? 0 : -1}
            className={`tab${tab === t.key ? " active" : ""}`}
            onClick={() => selectTab(t.key)}
            onKeyDown={(e) => {
              const i = TABS.findIndex((x) => x.key === t.key);
              const next = e.key === "ArrowRight" ? TABS[(i + 1) % TABS.length] : e.key === "ArrowLeft" ? TABS[(i + TABS.length - 1) % TABS.length] : undefined;
              if (!next) return;
              e.preventDefault();
              selectTab(next.key);
              document.getElementById(`tab-${next.key}`)?.focus();
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      <section className="card card-flush tab-panel" role="tabpanel" id="tab-panel" aria-labelledby={`tab-${tab}`}>
        {tab === "agents" && <AgentInventory projectId={projectId} detail={d} />}
        {tab === "scans" &&
          ((d.recent_scans ?? []).length === 0 ? (
            <EmptyState title="No scan has been uploaded yet" icon={<IconPlug size={28} />}>
              <p>
                <Link to={`/connect?project=${encodeURIComponent(projectId)}`} className="btn btn-primary">
                  Connect a repository
                </Link>
              </p>
            </EmptyState>
          ) : (
            <>
              <p className="tab-intro">The 20 most recent uploads. Open a scan to see its agents, warnings, and findings.</p>
              <DataTable columns={scanColumns} rows={d.recent_scans ?? []} rowKey={(s) => s.id} caption="Recent scans" initialSort={{ key: "received", dir: "desc" }} />
            </>
          ))}
        {tab === "members" &&
          (manage ? (
            <Members projectId={projectId} />
          ) : (
            <Notice tone="info" title="Only project owners and administrators can manage members">
              Your role in this project is {projectRoleLabel(role).toLowerCase()}. Ask an owner to change who has access.
            </Notice>
          ))}
        {tab === "tokens" &&
          (manage ? (
            <Tokens projectId={projectId} />
          ) : (
            <Notice tone="info" title="Only project owners and administrators can manage upload tokens">
              Your role in this project is {projectRoleLabel(role).toLowerCase()}. Ask an owner for a token.
            </Notice>
          ))}
      </section>
    </>
  );
}

