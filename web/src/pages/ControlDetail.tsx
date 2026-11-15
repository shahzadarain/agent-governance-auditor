// SPDX-License-Identifier: Apache-2.0

import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Catalog, Evidence, Mapping } from "../api/types";
import { IconArrowRight, IconExternal, IconFile, RollupIcon } from "../components/Icons";
import {
  Card,
  EmptyState,
  ErrorState,
  LoadingPage,
  MandatoryMark,
  MaturityBar,
  Notice,
  PageHeader,
  Pill,
  SeverityBadge,
  TextList,
  Time,
} from "../components/ui";
import { agentKeyFor, agentName, loadScanContext, paths, type ScanContext } from "../lib/data";
import { absoluteTime } from "../lib/format";
import {
  basisLabel,
  integrityLabel,
  maturityName,
  rollupOf,
  sourceTypeLabel,
  statusLabel,
  statusMeaning,
  strengthLabel,
  validityLabel,
} from "../lib/labels";
import { useAsync } from "../lib/useAsync";

/** Only http and https links become clickable. Anything else renders as text. */
export function safeHttpUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

export function StandardsList({ mappings }: { mappings: Mapping[] | null | undefined }) {
  if (!mappings || mappings.length === 0) return <p className="muted">No standards reference is recorded for this item.</p>;
  return (
    <>
      <p className="ref-note">
        <Pill tone="info">Reference only, not certification</Pill> These links point to related published guidance. They
        do not mean that the agent conforms to the standard.
      </p>
      <ul className="refs">
        {mappings.map((m, i) => {
          const href = safeHttpUrl(m.url);
          return (
            <li key={`${m.standard}-${m.requirement_id}-${i}`}>
              <div className="ref-head">
                <strong>
                  {m.standard} {m.version}
                </strong>
                <span className="mono">{m.requirement_id}</span>
              </div>
              <p>{m.rationale}</p>
              {href ? (
                <a href={href} target="_blank" rel="noopener noreferrer" className="ext-link">
                  {href}
                  <IconExternal size={14} />
                  <span className="sr-only"> (opens in a new tab)</span>
                </a>
              ) : (
                m.url && <span className="mono wrap">{m.url}</span>
              )}
            </li>
          );
        })}
      </ul>
    </>
  );
}

export function EvidenceCard({ e }: { e: Evidence }) {
  const credited = e.validity === "valid";
  return (
    <li className={`evidence${credited ? "" : " evidence-invalid"}`}>
      <div className="evidence-head">
        <span className="evidence-source">
          <IconFile size={16} />
          {sourceTypeLabel(e.source_type)}
        </span>
        <Pill tone={credited ? "neutral" : "warn"}>{validityLabel(e.validity)}</Pill>
        <span className="mono evidence-id">{e.evidence_id}</span>
      </div>
      <p className="evidence-summary">{e.summary}</p>
      {!credited && (
        <p className="evidence-warn">
          This item is not credited{e.validity_reason ? `: ${e.validity_reason}` : "."}
        </p>
      )}
      <dl className="evidence-facts">
        <div>
          <dt>Strength</dt>
          <dd>{strengthLabel(e.strength)}</dd>
        </div>
        <div>
          <dt>Integrity</dt>
          <dd>{integrityLabel(e.integrity)}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd title={absoluteTime(e.observed_at)}>
            <Time value={e.observed_at} fallback="Not recorded" />
          </dd>
        </div>
        <div>
          <dt>Valid until</dt>
          <dd title={e.valid_until ? absoluteTime(e.valid_until) : undefined}>{e.valid_until ? e.valid_until.slice(0, 10) : "No expiry stated"}</dd>
        </div>
        <div>
          <dt>Result</dt>
          <dd>
            {e.result} ({e.signal})
          </dd>
        </div>
        <div>
          <dt>Where</dt>
          <dd className="mono wrap">{e.source_location || "Not recorded"}</dd>
        </div>
        <div>
          <dt>Collector</dt>
          <dd className="mono wrap">{e.collector}</dd>
        </div>
      </dl>
      {(e.limitations ?? []).length > 0 && (
        <details className="disclosure">
          <summary>Limits of this evidence</summary>
          <TextList items={e.limitations} />
        </details>
      )}
    </li>
  );
}

interface Loaded {
  ctx: ScanContext;
  catalog: Catalog | null;
}

export function ControlDetail() {
  const { scanId = "", controlId = "" } = useParams();
  const [params] = useSearchParams();
  const agentParam = params.get("agent") ?? "";
  const state = useAsync<Loaded>(
    async (signal) => {
      const [ctx, catalog] = await Promise.all([loadScanContext(scanId, signal), api.controls(signal).catch(() => null)]);
      return { ctx, catalog };
    },
    [scanId],
  );

  if (state.status === "loading") return <LoadingPage label="Loading the control" />;
  if (state.status === "error") {
    return (
      <>
        <PageHeader title={controlId} />
        <ErrorState error={state.error} onRetry={() => state.reload()} />
      </>
    );
  }

  const { ctx, catalog } = state.data;
  const res = ctx.detail.result;
  const assessments = res.assessments ?? [];
  const assessment = assessments.find((a) => a.agent_id === agentParam) ?? assessments[0];
  const control = assessment?.controls?.find((c) => c.control_id === controlId);
  const baseCrumbs = [
    { label: "Overview", to: "/" },
    { label: ctx.project.name, to: paths.project(ctx.project.id) },
  ];

  if (!assessment || !control) {
    return (
      <>
        <PageHeader title={controlId} crumbs={[...baseCrumbs, { label: controlId }]} />
        <EmptyState title="This scan holds no result for this control">
          <p>
            The scan has no assessment of {controlId} for this agent. When a scan finds no agent, it assesses no control.
            That is not a pass.
          </p>
          <p>
            <Link to={paths.scan(scanId)} className="btn">
              Open the scan
            </Link>
          </p>
        </EmptyState>
      </>
    );
  }

  const agentId = assessment.agent_id;
  const key = agentKeyFor(ctx, agentId);
  const name = agentName(res.agents, agentId);
  const def = catalog?.controls.find((c) => c.id === controlId);
  const r = rollupOf(control.status);
  const allEvidence = res.evidence ?? [];
  const evidence = (control.evidence_refs ?? []).map((id) => allEvidence.find((e) => e.evidence_id === id)).filter((e): e is Evidence => !!e);
  const missingRefs = (control.evidence_refs ?? []).filter((id) => !allEvidence.some((e) => e.evidence_id === id));
  const findings = (res.findings ?? []).filter((f) => (control.finding_refs ?? []).includes(f.finding_id));
  const short = control.mandatory && control.applicable && control.maturity < control.min_maturity;
  const expired = evidence.filter((e) => e.validity === "expired").length;

  return (
    <>
      <PageHeader
        title={`${control.control_id} ${control.title}`}
        eyebrow={control.domain}
        lead={control.plain_language}
        crumbs={[...baseCrumbs, ...(key ? [{ label: name, to: paths.agent(key) }] : [{ label: name }]), { label: control.control_id }]}
      />

      <section className={`status-panel status-panel-${r}`} aria-labelledby="status-title" data-testid="control-status">
        <div className="status-panel-icon" aria-hidden="true">
          <RollupIcon rollup={r} size={34} />
        </div>
        <div className="status-panel-text">
          <p className="banner-kicker">Status for {name}</p>
          <h2 id="status-title">{statusLabel(control.status)}</h2>
          <p>{statusMeaning(control.status)}</p>
          <p className="status-reason">
            <strong>Exact reason:</strong> {control.status_reason || "No reason was recorded."}
          </p>
        </div>
        <dl className="banner-facts">
          <div>
            <dt>Maturity</dt>
            <dd>
              <MaturityBar value={control.maturity} required={control.mandatory && control.applicable ? control.min_maturity : undefined} />
              <span className="fact-sub">{maturityName(control.maturity)}</span>
            </dd>
          </div>
          <div>
            <dt>Requirement</dt>
            <dd>
              {control.mandatory ? (
                <>
                  <MandatoryMark min={control.min_maturity} />
                  <span className="fact-sub">
                    Needs level {control.min_maturity}. {short ? "Not met." : "Met."}
                  </span>
                </>
              ) : (
                <>
                  Not mandatory
                  <span className="fact-sub">Under the {ctx.detail.scan.profile} profile</span>
                </>
              )}
            </dd>
          </div>
          <div>
            <dt>Default severity</dt>
            <dd>
              <SeverityBadge severity={control.severity} />
              <span className="fact-sub">Weight {control.weight}</span>
            </dd>
          </div>
        </dl>
      </section>

      {expired > 0 && (
        <Notice tone="warn" title={`${expired === 1 ? "1 evidence item has" : `${expired} evidence items have`} expired`}>
          Expired evidence is not credited. Collect the evidence again and upload a new scan.
        </Notice>
      )}
      {control.status === "error" && (
        <Notice tone="warn" title="The check did not complete">
          An assessment error is not a pass. Run the scan again, or review this control by hand.
        </Notice>
      )}

      <div className="grid-2-1">
        <div className="stack">
          {control.next_action && (
            <Card title="Next action" className="next-card">
              <p className="next-action">
                <IconArrowRight size={20} />
                <span>{control.next_action}</span>
              </p>
            </Card>
          )}

          <Card title={`Evidence (${evidence.length})`} note="Each item says where it came from, how strong it is, and whether it can be credited.">
            {evidence.length === 0 ? (
              <p className="muted">
                No evidence item supports this control in this scan.{" "}
                {control.status === "missing" ? "The scanner looked for the control and did not find it." : ""}
              </p>
            ) : (
              <ul className="evidence-list">
                {evidence.map((e) => (
                  <EvidenceCard key={e.evidence_id} e={e} />
                ))}
              </ul>
            )}
            {missingRefs.length > 0 && (
              <p className="muted">
                The result refers to evidence that is not in this scan file: <span className="mono">{missingRefs.join(", ")}</span>
              </p>
            )}
          </Card>

          <Card title="How to fix it" note="Ordered steps from the control catalog.">
            <TextList items={control.remediation} ordered empty="No remediation step is recorded." />
          </Card>

          <Card title={`Related findings (${findings.length})`}>
            {findings.length === 0 ? (
              <p className="muted">No finding in this scan refers to this control.</p>
            ) : (
              <ul className="finding-links">
                {findings.map((f) => (
                  <li key={f.finding_id}>
                    <SeverityBadge severity={f.severity} />
                    <Link to={paths.finding(scanId, f.finding_id)}>{f.title}</Link>
                    {f.location?.path && (
                      <span className="mono muted wrap">
                        {f.location.path}
                        {f.location.line ? `:${f.location.line}` : ""}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card title="How it was assessed">
            <dl className="facts facts-1">
              <div>
                <dt>Does it apply?</dt>
                <dd>
                  {control.applicable ? "Yes" : "No"}. {basisLabel(control.applicability_basis)}.
                  {control.applicability_reason && <span className="fact-sub">{control.applicability_reason}</span>}
                </dd>
              </div>
              <div>
                <dt>Limit of a static scan</dt>
                <dd>
                  A static scan alone can support at most level {control.max_static_maturity} for this control. Higher
                  levels need test or runtime evidence.
                </dd>
              </div>
            </dl>
            {def ? (
              <>
                <h3 className="subhead">What each level requires</h3>
                <dl className="levels">
                  <div>
                    <dt>Level 2 · Implemented</dt>
                    <dd>{def.verification_rules.implementation}</dd>
                  </div>
                  <div>
                    <dt>Level 3 · Verified by tests</dt>
                    <dd>{def.verification_rules.tested}</dd>
                  </div>
                  <div>
                    <dt>Level 4 · Verified in operation</dt>
                    <dd>{def.verification_rules.operational}</dd>
                  </div>
                </dl>
                {(def.evidence_types ?? []).length > 0 && (
                  <>
                    <h3 className="subhead">Evidence that counts</h3>
                    <TextList items={def.evidence_types} />
                  </>
                )}
              </>
            ) : (
              <p className="muted">The control catalog could not be loaded, so the level rules are not shown.</p>
            )}
          </Card>

          <Card title="Limitations" note="What this assessment cannot tell you.">
            <TextList items={control.limitations} empty="No limitation is recorded for this result." />
          </Card>

          <Card title="Standards references">
            <StandardsList mappings={def?.standards_mappings} />
          </Card>
        </div>
      </div>
    </>
  );
}
