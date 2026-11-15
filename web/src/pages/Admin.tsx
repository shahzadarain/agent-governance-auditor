// SPDX-License-Identifier: Apache-2.0
//
// Audit events, users, the connect page, and the not-found page.

import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { AuditEvent, Project, User } from "../api/types";
import { useAuth } from "../auth";
import { ConnectGuide } from "../components/ConnectGuide";
import { errorText, PasswordInput } from "../components/forms";
import { IconList, IconSearch } from "../components/Icons";
import { DataTable, type Column } from "../components/table";
import { AsyncView, Card, EmptyState, ErrorState, Field, Notice, PageHeader, Pill, Skeleton, Time } from "../components/ui";
import { absoluteTime } from "../lib/format";
import { projectRoleLabel } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import { MIN_PASSWORD } from "./Setup";

// --- Audit events -------------------------------------------------------------------

export function detailText(detail: Record<string, unknown> | null | undefined): string {
  const entries = Object.entries(detail ?? {});
  if (entries.length === 0) return "";
  return entries.map(([k, v]) => `${k}: ${typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}`).join(", ");
}

const PAGE = 100;

function AuditTable({ project, projects }: { project: string; projects: Project[] }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [more, setMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState("");
  const first = useAsync((signal) => api.auditEvents({ project, limit: PAGE }, signal), [project]);

  useEffect(() => {
    if (first.status === "ready") {
      setEvents(first.data);
      setMore(first.data.length === PAGE);
    }
  }, [first.status, first.data]);

  const loadMore = async () => {
    const last = events[events.length - 1];
    if (!last) return;
    setLoadingMore(true);
    setMoreError("");
    try {
      const next = await api.auditEvents({ project, limit: PAGE, before: last.id });
      setEvents((e) => [...e, ...next]);
      setMore(next.length === PAGE);
    } catch (err) {
      setMoreError(errorText(err));
    } finally {
      setLoadingMore(false);
    }
  };

  const name = (id: string) => projects.find((p) => p.id === id)?.name ?? id;
  const columns: Column<AuditEvent>[] = [
    {
      key: "at",
      label: "When",
      render: (e) => (
        <>
          <Time value={e.at} />
          <span className="cell-sub">{absoluteTime(e.at)}</span>
        </>
      ),
    },
    { key: "action", label: "Action", rowHeader: true, render: (e) => <span className="mono">{e.action}</span> },
    {
      key: "actor",
      label: "Actor",
      render: (e) => (
        <>
          {e.actor_type}
          <span className="cell-sub mono">{e.actor_id}</span>
        </>
      ),
    },
    { key: "target", label: "Target", render: (e) => <span className="mono wrap">{e.target}</span> },
    { key: "project", label: "Project", render: (e) => (e.project_id ? name(e.project_id) : <span className="muted">Server</span>) },
    { key: "detail", label: "Detail", render: (e) => <span className="wrap">{detailText(e.detail) || <span className="muted">None</span>}</span> },
  ];

  if (first.status === "loading") return <div className="card-pad"><Skeleton lines={6} /></div>;
  if (first.status === "error") return <ErrorState error={first.error} onRetry={() => first.reload()} />;
  return (
    <>
      <DataTable columns={columns} rows={events} rowKey={(e) => String(e.id)} caption="Audit events, newest first" empty="No audit event is recorded for this selection." />
      <div className="table-foot">
        <span className="muted" aria-live="polite">
          {events.length} {events.length === 1 ? "event" : "events"} shown, newest first.
        </span>
        {more && (
          <button type="button" className="btn btn-small" onClick={() => void loadMore()} disabled={loadingMore}>
            {loadingMore ? "Loading…" : "Load older events"}
          </button>
        )}
        {moreError && <span className="field-error">{moreError}</span>}
      </div>
    </>
  );
}

export function AuditPage() {
  const { isAdmin } = useAuth();
  const projects = useAsync((signal) => api.projects(signal), []);
  const [params, setParams] = useSearchParams();

  return (
    <>
      <PageHeader
        title="Audit events"
        crumbs={[{ label: "Overview", to: "/" }, { label: "Audit events" }]}
        lead="A tamper-evident record of sign-ins, uploads, and changes to projects, members, and tokens. Each event holds the hash of the event before it."
      />
      <AsyncView state={projects}>
        {(list) => {
          const allowed = isAdmin ? list : list.filter((p) => p.role === "owner" || p.role === "reviewer");
          if (!isAdmin && allowed.length === 0) {
            return (
              <EmptyState title="Your role cannot see audit events" icon={<IconList size={28} />}>
                <p>
                  Audit events are visible to administrators, and to owners and reviewers of a project. You are a viewer,
                  or you are not a member of any project.
                </p>
              </EmptyState>
            );
          }
          const fallback = isAdmin ? "" : (allowed[0]?.id ?? "");
          const selected = params.get("project") ?? fallback;
          const valid = selected === "" ? isAdmin : allowed.some((p) => p.id === selected);
          return (
            <Card flush>
              <div className="filters">
                <div className="field">
                  <label htmlFor="audit-project">Project</label>
                  <select id="audit-project" value={valid ? selected : fallback} onChange={(e) => setParams(e.target.value ? { project: e.target.value } : {}, { replace: true })}>
                    {isAdmin && <option value="">All projects and server events</option>}
                    {allowed.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <AuditTable project={valid ? selected : fallback} projects={list} />
            </Card>
          );
        }}
      </AsyncView>
    </>
  );
}

// --- Users (administrators) -----------------------------------------------------------

const userColumns: Column<User>[] = [
  { key: "name", label: "Username", rowHeader: true, sort: (u) => u.username, render: (u) => u.username },
  { key: "role", label: "Role", sort: (u) => u.role, render: (u) => <Pill tone={u.role === "administrator" ? "info" : "neutral"}>{projectRoleLabel(u.role)}</Pill> },
  { key: "state", label: "State", render: (u) => (u.disabled ? <Pill tone="warn">Disabled</Pill> : "Active") },
  { key: "created", label: "Created", sort: (u) => Date.parse(u.created_at), render: (u) => <Time value={u.created_at} /> },
];

export function UsersPage() {
  const { isAdmin } = useAuth();
  const state = useAsync((signal) => (isAdmin ? api.users(signal) : Promise.resolve<User[]>([])), [isAdmin]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "danger" | "success"; text: string } | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.createUser(username.trim(), password, role);
      setMsg({ tone: "success", text: `The account ${r.user.username} exists now. Add it to a project so that it can see data.` });
      setUsername("");
      setPassword("");
      state.reload(true);
    } catch (err) {
      setMsg({ tone: "danger", text: errorText(err) });
    } finally {
      setBusy(false);
    }
  };

  const header = (
    <PageHeader
      title="Users"
      crumbs={[{ label: "Overview", to: "/" }, { label: "Users" }]}
      lead="Accounts on this server. A user sees a project only after an owner or an administrator adds the user as a member."
    />
  );
  if (!isAdmin) {
    return (
      <>
        {header}
        <Notice tone="info" title="Only an administrator can manage users">
          Your account has the user role.
        </Notice>
      </>
    );
  }
  return (
    <>
      {header}
      <Card title="Accounts" flush>
        <AsyncView state={state}>{(users) => <DataTable columns={userColumns} rows={users} rowKey={(u) => u.id} caption="Users" initialSort={{ key: "name", dir: "asc" }} />}</AsyncView>
      </Card>
      <Card title="Create a user" note="Give the password to the person through a safe channel. There is no email invitation.">
        <form className="form-inline" onSubmit={submit} aria-label="Create a user">
          <Field label="Username" hint="3 to 64 characters: letters, digits, dot, underscore, hyphen, or @.">
            {({ id, describedBy }) => (
              <input id={id} value={username} onChange={(e) => setUsername(e.target.value)} aria-describedby={describedBy} minLength={3} maxLength={64} required autoCapitalize="none" spellCheck={false} autoComplete="off" />
            )}
          </Field>
          <Field label="Password" hint={`At least ${MIN_PASSWORD} characters.`}>
            {({ id, describedBy }) => (
              <PasswordInput id={id} value={password} onChange={setPassword} describedBy={describedBy} autoComplete="new-password" minLength={MIN_PASSWORD} />
            )}
          </Field>
          <Field label="Role" hint="An administrator sees and manages everything.">
            {({ id, describedBy }) => (
              <select id={id} value={role} onChange={(e) => setRole(e.target.value)} aria-describedby={describedBy}>
                <option value="user">User</option>
                <option value="administrator">Administrator</option>
              </select>
            )}
          </Field>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Creating…" : "Create user"}
            </button>
          </div>
        </form>
        <div aria-live="polite">{msg && <Notice tone={msg.tone}>{msg.text}</Notice>}</div>
      </Card>
    </>
  );
}

// --- Connect and not found ------------------------------------------------------------

export function ConnectPage() {
  const [params] = useSearchParams();
  return (
    <>
      <PageHeader
        title="Connect a repository"
        crumbs={[{ label: "Overview", to: "/" }, { label: "Connect a repository" }]}
        lead="Four steps: choose a project, create an upload token, run one scan, and check that the result arrived."
      />
      <Card>
        <ConnectGuide initialProjectId={params.get("project") ?? undefined} />
      </Card>
    </>
  );
}

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="This address does not match any page" icon={<IconSearch size={28} />}>
        <p>Check the link, or start again from the overview.</p>
        <p>
          <Link to="/" className="btn btn-primary">
            Go to the overview
          </Link>
        </p>
      </EmptyState>
    </>
  );
}
