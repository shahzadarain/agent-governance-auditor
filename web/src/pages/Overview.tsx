// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { OverviewResponse, ProjectOverview } from "../api/types";
import { ConnectGuide } from "../components/ConnectGuide";
import { DecisionIcon, IconArrowRight, IconClock, IconFolder, IconPlug } from "../components/Icons";
import { Card, ErrorState, LoadingPage, Notice, PageHeader, Pill, Time } from "../components/ui";
import { paths } from "../lib/data";
import { plural } from "../lib/format";
import { decisionKey, projectRoleLabel, type DecisionKey } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

export interface DecisionCounts {
  allow: number;
  review: number;
  block: number;
  unknown: number;
  total: number;
}

export function countDecisions(decisions: Record<string, number> | null | undefined): DecisionCounts {
  const c: DecisionCounts = { allow: 0, review: 0, block: 0, unknown: 0, total: 0 };
  for (const [k, n] of Object.entries(decisions ?? {})) {
    c[decisionKey(k)] += n;
    c.total += n;
  }
  return c;
}

/** The one sentence a risk owner reads first. */
export function headline(c: DecisionCounts): { text: string; tone: DecisionKey } {
  const agents = (n: number) => (n === 1 ? "agent" : "agents");
  if (c.total === 0) return { text: "No agents have been assessed yet", tone: "unknown" };
  if (c.block > 0) {
    return { text: `${c.block} of ${c.total} ${agents(c.total)} ${c.block === 1 ? "is" : "are"} blocked from release`, tone: "block" };
  }
  if (c.review > 0) {
    return {
      text: `${c.review} of ${c.total} ${agents(c.total)} ${c.review === 1 ? "needs" : "need"} a review before release`,
      tone: "review",
    };
  }
  if (c.unknown > 0) {
    return { text: `${c.unknown} of ${c.total} ${agents(c.total)} ${c.unknown === 1 ? "has" : "have"} no readable decision`, tone: "unknown" };
  }
  return {
    text: c.total === 1 ? "The 1 assessed agent meets its release policy" : `All ${c.total} agents meet their release policy`,
    tone: "allow",
  };
}

const ORDER: { key: DecisionKey; outcome: string; phrase: string }[] = [
  { key: "block", outcome: "BLOCK", phrase: "Blocked" },
  { key: "review", outcome: "REVIEW_REQUIRED", phrase: "Need review" },
  { key: "allow", outcome: "ALLOW", phrase: "Allowed" },
  { key: "unknown", outcome: "", phrase: "Undetermined" },
];

export function DecisionBar({ counts }: { counts: DecisionCounts }) {
  if (counts.total === 0) return null;
  const parts = ORDER.filter((o) => counts[o.key] > 0);
  const label = parts.map((o) => `${counts[o.key]} ${o.phrase.toLowerCase()}`).join(", ");
  return (
    <div className="dbar" role="img" aria-label={`Agents by release decision: ${label}`}>
      {parts.map((o) => (
        <span key={o.key} className={`dbar-seg dbar-${o.key}`} style={{ flexGrow: counts[o.key] }} />
      ))}
    </div>
  );
}

export function DecisionCountsRow({ counts }: { counts: DecisionCounts }) {
  return (
    <ul className="dcounts">
      {ORDER.filter((o) => o.key !== "unknown" || counts.unknown > 0).map((o) => (
        <li key={o.key} className={`dcount dcount-${o.key}${counts[o.key] === 0 ? " zero" : ""}`}>
          <DecisionIcon decision={o.key} size={18} />
          <span className="dcount-num">{counts[o.key]}</span>
          <span className="dcount-label">{o.phrase}</span>
        </li>
      ))}
    </ul>
  );
}

function ProjectCard({ name, id, role, ov }: { name: string; id: string; role?: string; ov: ProjectOverview }) {
  const counts = countDecisions(ov.decisions);
  const noAgent = ov.scan_count > 0 && ov.agent_count === 0;
  return (
    <article className="project-card">
      <header>
        <h3>
          <Link to={paths.project(id)}>{name}</Link>
        </h3>
        <Pill>{projectRoleLabel(role)}</Pill>
      </header>
      {ov.scan_count === 0 ? (
        <div className="project-empty">
          <p>No scan has been uploaded to this project yet.</p>
          <Link to={`/connect?project=${encodeURIComponent(id)}`} className="btn btn-small">
            <IconPlug size={15} />
            Connect a repository
          </Link>
        </div>
      ) : (
        <>
          {noAgent ? (
            <Notice tone="warn" title="The latest scan found no AI agent">
              This is not a pass. No control was assessed.
            </Notice>
          ) : (
            <>
              <DecisionBar counts={counts} />
              <DecisionCountsRow counts={counts} />
            </>
          )}
          <dl className="project-facts">
            <div>
              <dt>Open findings</dt>
              <dd>
                <span className={ov.open_critical > 0 ? "num-critical" : "num-zero"}>{ov.open_critical} critical</span>
                <span aria-hidden="true"> · </span>
                <span className={ov.open_high > 0 ? "num-high" : "num-zero"}>{ov.open_high} high</span>
              </dd>
            </div>
            <div>
              <dt>Latest scan</dt>
              <dd>
                <Time value={ov.latest_scan_at} />
                <span className="muted"> · {plural(ov.scan_count, "scan")}</span>
              </dd>
            </div>
          </dl>
        </>
      )}
      <footer>
        <Link to={paths.project(id)} className="link-arrow">
          Open project
          <IconArrowRight size={16} />
        </Link>
      </footer>
    </article>
  );
}

function OverviewBody({ data }: { data: OverviewResponse }) {
  const t = data.totals;
  const counts = countDecisions(t.decisions);
  const h = headline(counts);
  const nothingYet = t.scans === 0;

  if (nothingYet) {
    return (
      <>
        <PageHeader
          title="Connect your first repository"
          lead="The dashboard shows what the scanner uploads. Follow the four steps below. It takes a few minutes."
        />
        <Card>
          <ConnectGuide />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader title="Overview" lead="The current release decision of every agent you can see, across all projects." />
      <section className={`hero hero-${h.tone}`} aria-labelledby="hero-title">
        <div className="hero-icon" aria-hidden="true">
          <DecisionIcon decision={h.tone} size={34} />
        </div>
        <div className="hero-text">
          <h2 id="hero-title" data-testid="headline">
            {h.text}
          </h2>
          <p>
            {plural(t.agents, "agent")} in {plural(t.projects, "project")}. {counts.block} blocked, {counts.review} need
            review, {counts.allow} allowed.
            {counts.block > 0 ? " A blocked agent has at least one mandatory control that is not met." : ""}
          </p>
          <DecisionBar counts={counts} />
        </div>
      </section>

      <div className="stat-row">
        <div className="stat-card">
          <span className="stat-card-label">Open critical findings</span>
          <span className={`stat-card-value ${t.open_critical > 0 ? "num-critical" : ""}`}>{t.open_critical}</span>
          <span className="stat-card-hint">In the latest scan of each project</span>
        </div>
        <div className="stat-card">
          <span className="stat-card-label">Open high findings</span>
          <span className={`stat-card-value ${t.open_high > 0 ? "num-high" : ""}`}>{t.open_high}</span>
          <span className="stat-card-hint">In the latest scan of each project</span>
        </div>
        <div className="stat-card">
          <span className="stat-card-label">Agents assessed</span>
          <span className="stat-card-value">{t.agents}</span>
          <span className="stat-card-hint">
            {ORDER.filter((o) => counts[o.key] > 0)
              .map((o) => `${counts[o.key]} ${o.phrase.toLowerCase()}`)
              .join(", ") || "None yet"}
          </span>
        </div>
        <div className="stat-card">
          <span className="stat-card-label">Latest scan</span>
          <span className="stat-card-value stat-card-value-text">
            <IconClock size={20} />
            <Time value={t.latest_scan_at} />
          </span>
          <span className="stat-card-hint">{plural(t.scans, "scan")} stored</span>
        </div>
      </div>

      <section aria-labelledby="projects-title" className="section">
        <div className="section-head">
          <h2 id="projects-title">
            <IconFolder size={20} />
            Projects
          </h2>
          <Link to="/projects" className="link-arrow">
            All projects
            <IconArrowRight size={16} />
          </Link>
        </div>
        <div className="project-grid">
          {data.projects.map(({ project, overview }) => (
            <ProjectCard key={project.id} id={project.id} name={project.name} role={project.role} ov={overview} />
          ))}
        </div>
      </section>
    </>
  );
}

export function Overview() {
  const state = useAsync((signal) => api.overview(signal), []);
  if (state.status === "loading") return <LoadingPage label="Loading the overview" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title="Overview" />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }
  return <OverviewBody data={state.data} />;
}
