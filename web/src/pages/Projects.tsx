// SPDX-License-Identifier: Apache-2.0

import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { CreateProjectForm } from "../components/forms";
import { IconFolder } from "../components/Icons";
import { DataTable, type Column } from "../components/table";
import { AsyncView, Card, DecisionChip, EmptyState, Notice, PageHeader, Pill, Time } from "../components/ui";
import { paths } from "../lib/data";
import { projectRoleLabel } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import type { OverviewResponse } from "../api/types";

type Row = OverviewResponse["projects"][number];

const columns: Column<Row>[] = [
  {
    key: "name",
    label: "Project",
    rowHeader: true,
    sort: (r) => r.project.name,
    render: (r) => (
      <>
        <Link to={paths.project(r.project.id)}>{r.project.name}</Link>
        <span className="cell-sub mono">{r.project.slug}</span>
      </>
    ),
  },
  { key: "role", label: "Your role", sort: (r) => r.project.role ?? "", render: (r) => <Pill>{projectRoleLabel(r.project.role)}</Pill> },
  { key: "agents", label: "Agents", align: "right", sort: (r) => r.overview.agent_count, render: (r) => r.overview.agent_count },
  { key: "scans", label: "Scans", align: "right", sort: (r) => r.overview.scan_count, render: (r) => r.overview.scan_count },
  {
    key: "crit",
    label: "Critical / high",
    align: "right",
    sort: (r) => r.overview.open_critical * 1000 + r.overview.open_high,
    render: (r) => (
      <>
        <span className={r.overview.open_critical > 0 ? "num-critical" : "num-zero"}>{r.overview.open_critical}</span>
        {" / "}
        <span className={r.overview.open_high > 0 ? "num-high" : "num-zero"}>{r.overview.open_high}</span>
      </>
    ),
  },
  {
    key: "decision",
    label: "Latest scan decision",
    sort: (r) => r.overview.latest_decision,
    render: (r) => (r.overview.scan_count > 0 ? <DecisionChip decision={r.overview.latest_decision} /> : <span className="muted">No scan yet</span>),
  },
  {
    key: "latest",
    label: "Latest scan",
    sort: (r) => (r.overview.latest_scan_at ? Date.parse(r.overview.latest_scan_at) : null),
    render: (r) => <Time value={r.overview.latest_scan_at} fallback="Never" />,
  },
];

export function Projects() {
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const state = useAsync((signal) => api.overview(signal), []);

  return (
    <>
      <PageHeader
        title="Projects"
        lead="A project groups the agents of one repository or one team. You see the projects that you are a member of."
        crumbs={[{ label: "Overview", to: "/" }, { label: "Projects" }]}
      />
      <Card title="Your projects" flush>
        <AsyncView state={state}>
          {(data) =>
            data.projects.length === 0 ? (
              <EmptyState title="No projects yet" icon={<IconFolder size={28} />}>
                <p>
                  {isAdmin
                    ? "Create the first project below. Then connect a repository to it."
                    : "You are not a member of any project. Ask an administrator to add you."}
                </p>
              </EmptyState>
            ) : (
              <DataTable columns={columns} rows={data.projects} rowKey={(r) => r.project.id} caption="Projects" initialSort={{ key: "name", dir: "asc" }} />
            )
          }
        </AsyncView>
      </Card>

      <Card title="Create a project" note="A new project starts empty. Connect a repository to fill it.">
        {isAdmin ? (
          <CreateProjectForm onCreated={(p) => navigate(`/connect?project=${encodeURIComponent(p.id)}`)} />
        ) : (
          <Notice tone="info" title="Only an administrator can create a project">
            Your account has the user role. Ask an administrator to create the project and to add you as an owner,
            reviewer, or viewer.
          </Notice>
        )}
      </Card>
    </>
  );
}
