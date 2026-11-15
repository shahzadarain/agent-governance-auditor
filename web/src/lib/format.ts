// SPDX-License-Identifier: Apache-2.0

import type { AgentScan, Evidence } from "../api/types";

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

/** "3 hours ago", "in 2 days", or "just now". Returns "" for a bad date. */
export function relativeTime(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const diff = Math.round((t - now.getTime()) / 1000);
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "always" });
  for (const [unit, secs] of UNITS) {
    if (abs >= secs) return rtf.format(Math.trunc(diff / secs), unit);
  }
  return rtf.format(diff < 0 ? -1 : 1, "minute");
}

/** A full, unambiguous timestamp in UTC. */
export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  return new Date(t).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC").replace(/Z$/, " UTC");
}

export function shortDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  return new Date(t).toISOString().slice(0, 10);
}

export function shortCommit(sha: string | null | undefined): string {
  if (!sha || sha === "unknown") return "no commit";
  return sha.slice(0, 8);
}

export function plural(n: number, one: string, many?: string): string {
  return `${n} ${n === 1 ? one : (many ?? `${one}s`)}`;
}

export function formatLocation(loc: { path: string; line?: number } | null | undefined): string {
  if (!loc || !loc.path) return "";
  return loc.line ? `${loc.path}:${loc.line}` : loc.path;
}

// --- Evidence freshness -------------------------------------------------------

export interface Freshness {
  total: number;
  valid: number;
  expired: number;
  /** Other reasons an item cannot be credited (mismatch, unbound, bad signature, malformed). */
  otherInvalid: number;
  /** Earliest valid_until among valid items that state an expiry. */
  nextExpiry: string | null;
  /** Number of valid items that state no expiry. */
  noExpiry: number;
}

export function evidenceFreshness(items: Evidence[]): Freshness {
  const f: Freshness = { total: items.length, valid: 0, expired: 0, otherInvalid: 0, nextExpiry: null, noExpiry: 0 };
  for (const e of items) {
    if (e.validity === "valid") {
      f.valid++;
      if (e.valid_until) {
        if (f.nextExpiry === null || Date.parse(e.valid_until) < Date.parse(f.nextExpiry)) f.nextExpiry = e.valid_until;
      } else {
        f.noExpiry++;
      }
    } else if (e.validity === "expired") {
      f.expired++;
    } else {
      f.otherInvalid++;
    }
  }
  return f;
}

// --- Score history ------------------------------------------------------------

/** Scans are comparable only when policy pack, policy version, and profile match. */
export function policyKey(s: Pick<AgentScan, "policy_pack" | "policy_version" | "profile">): string {
  return `${s.policy_pack}@${s.policy_version}#${s.profile}`;
}

export interface HistorySegment {
  key: string;
  profile: string;
  policy: string;
  points: AgentScan[];
}

/**
 * Splits an agent history (any order) into runs of consecutive scans that
 * share one policy key, oldest first. Points in different segments must
 * never be joined by a line.
 */
export function historySegments(scans: AgentScan[]): HistorySegment[] {
  const sorted = [...scans].sort((a, b) => Date.parse(a.received_at) - Date.parse(b.received_at));
  const out: HistorySegment[] = [];
  for (const s of sorted) {
    const key = policyKey(s);
    const last = out[out.length - 1];
    if (last && last.key === key) {
      last.points.push(s);
    } else {
      out.push({ key, profile: s.profile, policy: `${s.policy_pack} ${s.policy_version}`, points: [s] });
    }
  }
  return out;
}
