// SPDX-License-Identifier: Apache-2.0
//
// Loaders and small helpers shared by several pages.

import { api } from "../api/client";
import type { Agent, Control, Evidence, Finding, Project, ScanAgent, ScanDetail } from "../api/types";

// A stored scan never changes, so its payload can be reused while the page
// stays open. The cache lives in memory only and holds a few scans.
const scanCache = new Map<string, Promise<ScanDetail>>();
const MAX_CACHED = 6;

export function loadScan(id: string): Promise<ScanDetail> {
  const hit = scanCache.get(id);
  if (hit) return hit;
  const p = api.scan(id);
  scanCache.set(id, p);
  p.catch(() => scanCache.delete(id));
  if (scanCache.size > MAX_CACHED) {
    const oldest = scanCache.keys().next().value;
    if (oldest !== undefined) scanCache.delete(oldest);
  }
  return p;
}

export function clearScanCache(): void {
  scanCache.clear();
}

export interface ScanContext {
  detail: ScanDetail;
  project: Project;
  /** Agents of the project as the server tracks them; used to link back to an agent page. */
  projectAgents: Agent[];
}

export async function loadScanContext(scanId: string, signal: AbortSignal): Promise<ScanContext> {
  const detail = await loadScan(scanId);
  const [pd, projectAgents] = await Promise.all([
    api.project(detail.scan.project_id, signal),
    api.projectAgents(detail.scan.project_id, signal),
  ]);
  return { detail, project: pd.project, projectAgents };
}

export function agentKeyFor(ctx: ScanContext, agentId: string): string | undefined {
  return ctx.projectAgents.find((a) => a.agent_id === agentId)?.key;
}

export function agentName(agents: ScanAgent[] | null | undefined, agentId: string): string {
  if (agentId === "*") return "All agents (repository level)";
  return agents?.find((a) => a.id === agentId)?.name || agentId;
}

/** Evidence that applies to one agent: its own items and repository-level items. */
export function evidenceFor(all: Evidence[] | null | undefined, agentId: string): Evidence[] {
  return (all ?? []).filter((e) => e.agent_id === agentId || e.agent_id === "*");
}

export function findingsFor(all: Finding[] | null | undefined, agentId: string): Finding[] {
  return (all ?? []).filter((f) => f.agent_id === agentId || f.agent_id === "*");
}

/** Domains in catalog order, each with its items. */
export function groupByDomain<T extends { domain: string }>(items: T[]): { domain: string; items: T[] }[] {
  const out: { domain: string; items: T[] }[] = [];
  for (const it of items) {
    let g = out.find((d) => d.domain === it.domain);
    if (!g) {
      g = { domain: it.domain, items: [] };
      out.push(g);
    }
    g.items.push(it);
  }
  return out.sort((a, b) => a.domain.localeCompare(b.domain));
}

/** "A: Accountability" becomes { letter: "A", name: "Accountability" }. */
export function splitDomain(domain: string): { letter: string; name: string } {
  const m = /^([A-Z]):\s*(.+)$/.exec(domain);
  return m ? { letter: m[1] ?? "", name: m[2] ?? domain } : { letter: "", name: domain };
}

export function controlTitle(catalog: Control[] | undefined, id: string): string {
  return catalog?.find((c) => c.id === id)?.title ?? "";
}

const e = encodeURIComponent;

export const paths = {
  project: (id: string, tab?: string) => `/projects/${e(id)}${tab ? `?tab=${tab}` : ""}`,
  agent: (key: string) => `/agents/${e(key)}`,
  compare: (key: string, after?: string, before?: string) =>
    `/agents/${e(key)}/compare${after && before ? `?after=${e(after)}&before=${e(before)}` : ""}`,
  scan: (id: string) => `/scans/${e(id)}`,
  findings: (scanId: string, q: Record<string, string> = {}) => {
    const qs = new URLSearchParams(q).toString();
    return `/scans/${e(scanId)}/findings${qs ? `?${qs}` : ""}`;
  },
  finding: (scanId: string, findingId: string) => `/scans/${e(scanId)}/findings/${e(findingId)}`,
  control: (scanId: string, controlId: string, agentId: string) =>
    `/scans/${e(scanId)}/controls/${e(controlId)}?agent=${e(agentId)}`,
};
