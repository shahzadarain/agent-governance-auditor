// SPDX-License-Identifier: Apache-2.0
//
// Read-only reference pages: the controls catalog and the policy profiles.

import { useState } from "react";
import { api } from "../api/client";
import type { Catalog, Control, Profile } from "../api/types";
import { IconCheck, IconLock } from "../components/Icons";
import { AsyncView, Card, PageHeader, Pill, SeverityBadge, TextList } from "../components/ui";
import { groupByDomain, splitDomain } from "../lib/data";
import { plural } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { StandardsList } from "./ControlDetail";

function CatalogControl({ c }: { c: Control }) {
  return (
    <li className="catalog-item" id={c.id}>
      <details>
        <summary>
          <span className="catalog-id mono">{c.id}</span>
          <span className="catalog-title">
            <strong>{c.title}</strong>
            <span className="catalog-plain">{c.plain_language}</span>
          </span>
          <SeverityBadge severity={c.severity} />
        </summary>
        <div className="catalog-body">
          <dl className="facts facts-1">
            <div>
              <dt>Intent</dt>
              <dd>{c.intent}</dd>
            </div>
            <div>
              <dt>When it applies</dt>
              <dd>
                {c.applicability.mode === "always"
                  ? "To every agent."
                  : `When the agent has one of these capabilities: ${(c.applicability.capabilities_any ?? []).join(", ") || "none listed"}.`}
                <span className="fact-sub">{c.applicability.rationale}</span>
              </dd>
            </div>
            <div>
              <dt>Default weight</dt>
              <dd>{c.default_weight}</dd>
            </div>
          </dl>
          <h4>What each maturity level requires</h4>
          <dl className="levels">
            <div>
              <dt>Level 2 · Implemented</dt>
              <dd>{c.verification_rules.implementation}</dd>
            </div>
            <div>
              <dt>Level 3 · Verified by tests</dt>
              <dd>{c.verification_rules.tested}</dd>
            </div>
            <div>
              <dt>Level 4 · Verified in operation</dt>
              <dd>{c.verification_rules.operational}</dd>
            </div>
          </dl>
          <p className="muted">A static scan alone can support at most level {c.verification_rules.max_static_maturity}.</p>
          <div className="grid-1-1 grid-tight">
            <div>
              <h4>Example that counts</h4>
              <p>{c.examples.positive}</p>
            </div>
            <div>
              <h4>Example that does not count</h4>
              <p>{c.examples.negative}</p>
            </div>
          </div>
          <h4>Remediation</h4>
          <TextList items={c.remediation} ordered empty="No remediation step is recorded." />
          <h4>Limitations</h4>
          <TextList items={c.limitations} empty="No limitation is recorded." />
          <h4>Standards references</h4>
          <StandardsList mappings={c.standards_mappings} />
        </div>
      </details>
    </li>
  );
}

export function CatalogPage() {
  const state = useAsync((signal) => api.controls(signal), []);
  const [q, setQ] = useState("");
  return (
    <>
      <PageHeader
        title="Controls catalog"
        crumbs={[{ label: "Overview", to: "/" }, { label: "Controls catalog" }]}
        lead="The 24 governance controls that every scan assesses, in six domains. This page describes the controls. It does not show the status of any agent."
      />
      <AsyncView state={state}>
        {(cat: Catalog) => {
          const needle = q.trim().toLowerCase();
          const list = cat.controls.filter(
            (c) => !needle || [c.id, c.title, c.plain_language, c.intent, c.domain].some((v) => v.toLowerCase().includes(needle)),
          );
          return (
            <>
              <div className="filters filters-plain">
                <div className="field field-grow">
                  <label htmlFor="cat-q">Search controls</label>
                  <input id="cat-q" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="ID, title, or word" />
                </div>
                <p className="filters-count" aria-live="polite">
                  {plural(list.length, "control")} · policy pack <span className="mono">{cat.pack}</span> version{" "}
                  <span className="mono">{cat.version}</span>
                </p>
              </div>
              {groupByDomain(list).map((g) => {
                const d = splitDomain(g.domain);
                return (
                  <Card
                    key={g.domain}
                    flush
                    title={
                      <>
                        {d.letter && <span className="domain-letter">{d.letter}</span>}
                        {d.name}
                      </>
                    }
                  >
                    <ul className="catalog">
                      {g.items.map((c) => (
                        <CatalogControl key={c.id} c={c} />
                      ))}
                    </ul>
                  </Card>
                );
              })}
              {list.length === 0 && <p className="muted">No control matches this search.</p>}
            </>
          );
        }}
      </AsyncView>
    </>
  );
}

function required(p: Profile, id: string): number | null {
  if (!(p.mandatory_controls ?? []).includes(id)) return null;
  return p.control_min_maturity?.[id] ?? p.min_maturity;
}

export function PoliciesPage() {
  const state = useAsync(
    async (signal) => {
      const [profiles, catalog] = await Promise.all([api.policies(signal), api.controls(signal)]);
      return { profiles, catalog };
    },
    [],
  );
  return (
    <>
      <PageHeader
        title="Policies and profiles"
        crumbs={[{ label: "Overview", to: "/" }, { label: "Policies and profiles" }]}
        lead="A profile says which controls are mandatory and how mature each must be. A scan uses one profile. This view is read-only: profiles change through versioned policy files, not through the dashboard."
      />
      <AsyncView state={state}>
        {({ profiles, catalog }) => (
          <>
            <div className="profile-grid">
              {profiles.map((p) => (
                <Card key={p.name} title={p.name} note={`Version ${p.version}`} className="profile-card">
                  <p>{p.description}</p>
                  <dl className="facts facts-1">
                    <div>
                      <dt>Mandatory controls</dt>
                      <dd>{(p.mandatory_controls ?? []).length} of {catalog.controls.length}</dd>
                    </div>
                    <div>
                      <dt>Required maturity</dt>
                      <dd>Level {p.min_maturity} unless a control states its own level</dd>
                    </div>
                    <div>
                      <dt>Signed evidence</dt>
                      <dd>{p.require_signed_evidence ? "Required for levels 3 and 4" : "Not required"}</dd>
                    </div>
                    <div>
                      <dt>Review workflow</dt>
                      <dd>
                        {p.review_workflow
                          ? "On: a shortfall that is not a failure gives REVIEW REQUIRED"
                          : "Off: a shortfall gives BLOCK"}
                      </dd>
                    </div>
                  </dl>
                </Card>
              ))}
            </div>
            <Card title="Which controls each profile requires" note="The number is the maturity level a mandatory control must reach (1 to 4)." flush>
              <div className="table-wrap" tabIndex={0} role="region" aria-label="Controls required by each profile">
                <table className="table table-compact">
                  <thead>
                    <tr>
                      <th scope="col">Control</th>
                      {profiles.map((p) => (
                        <th scope="col" key={p.name}>
                          {p.name}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {catalog.controls.map((c) => (
                      <tr key={c.id}>
                        <th scope="row">
                          <span className="mono">{c.id}</span> {c.title}
                        </th>
                        {profiles.map((p) => {
                          const lvl = required(p, c.id);
                          return (
                            <td key={p.name}>
                              {lvl === null ? (
                                <span className="muted">Not mandatory</span>
                              ) : (
                                <span className="mandatory">
                                  <IconLock size={12} />
                                  Mandatory, level {lvl}
                                </span>
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <p className="muted">
              <IconCheck size={14} /> <Pill>Read-only</Pill> Policy pack <span className="mono">{catalog.pack}</span>, version{" "}
              <span className="mono">{catalog.version}</span>.
            </p>
          </>
        )}
      </AsyncView>
    </>
  );
}
