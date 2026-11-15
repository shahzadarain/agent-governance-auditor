// SPDX-License-Identifier: Apache-2.0
//
// Hand-drawn SVG charts. No chart library.

import { useEffect, useRef, useState } from "react";
import type { AgentScan } from "../api/types";
import { absoluteTime, historySegments, shortCommit, shortDate } from "../lib/format";
import { decisionName, SCORE_NOTE } from "../lib/labels";

/** Score dial. The score is illustrative: it never decides the release. */
export function ScoreDial({ value }: { value: number | null }) {
  const r = 62;
  const sweep = 270;
  const circ = 2 * Math.PI * r;
  const arc = (circ * sweep) / 360;
  const v = value === null ? 0 : Math.max(0, Math.min(100, value));
  const filled = (arc * v) / 100;
  const label =
    value === null
      ? "No score: there is not enough evidence. The score is illustrative only."
      : `Maturity score ${v} out of 100, illustrative only.`;
  return (
    <figure className="dial">
      <svg viewBox="0 0 160 160" width="168" height="168" role="img" aria-label={label}>
        <g transform="rotate(135 80 80)" fill="none" strokeWidth="12" strokeLinecap="round">
          <circle cx="80" cy="80" r={r} className="dial-track" strokeDasharray={`${arc} ${circ}`} />
          {value !== null && v > 0 && (
            <circle cx="80" cy="80" r={r} className="dial-value" strokeDasharray={`${filled} ${circ}`} />
          )}
        </g>
        {value === null ? (
          <>
            <text x="80" y="78" textAnchor="middle" className="dial-none">
              No score
            </text>
            <text x="80" y="98" textAnchor="middle" className="dial-unit">
              insufficient evidence
            </text>
          </>
        ) : (
          <>
            <text x="80" y="88" textAnchor="middle" className="dial-number">
              {v}
            </text>
            <text x="80" y="110" textAnchor="middle" className="dial-unit">
              out of 100
            </text>
          </>
        )}
      </svg>
      <figcaption>
        <span className="dial-title">Maturity score</span>
        <span className="dial-note">{SCORE_NOTE}</span>
      </figcaption>
    </figure>
  );
}

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T | null>(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    setW(el.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0]?.contentRect.width;
      if (cw) setW(Math.round(cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

/**
 * Score history. A line joins only scans that share policy pack, policy
 * version, and profile. A policy change shows as a break with a marker.
 */
export function ScoreHistory({ scans }: { scans: AgentScan[] }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const segments = historySegments(scans);
  const total = segments.reduce((n, s) => n + s.points.length, 0);
  const H = 190;
  const pad = { l: 38, r: 18, t: 30, b: 34 };
  const W = Math.max(width, 280);
  const innerW = W - pad.l - pad.r;
  const innerH = H - pad.t - pad.b;
  const x = (i: number) => (total <= 1 ? pad.l + innerW / 2 : pad.l + (innerW * i) / (total - 1));
  const y = (v: number) => pad.t + innerH * (1 - v / 100);

  let index = 0;
  const drawn = segments.map((seg) => {
    const pts = seg.points.map((p) => ({ p, i: index++ }));
    return { seg, pts };
  });
  const hasBreak = segments.length > 1;
  const labelEvery = Math.max(1, Math.ceil(total / Math.max(1, Math.floor(innerW / 84))));

  const summary =
    `Score history of ${total} ${total === 1 ? "scan" : "scans"}` +
    (hasBreak ? `, in ${segments.length} groups that are not comparable because the policy changed.` : ".");

  return (
    <div className="history" ref={ref}>
      {width > 0 && (
        <svg width={W} height={H} role="img" aria-label={summary} className="history-svg">
          {[0, 50, 100].map((g) => (
            <g key={g}>
              <line x1={pad.l} x2={W - pad.r} y1={y(g)} y2={y(g)} className="history-grid" />
              <text x={pad.l - 8} y={y(g) + 4} textAnchor="end" className="history-axis">
                {g}
              </text>
            </g>
          ))}
          {drawn.map(({ seg, pts }, si) => {
            const scored = pts.filter((q) => q.p.score !== null);
            const path = scored.map((q, k) => `${k === 0 ? "M" : "L"}${x(q.i).toFixed(1)} ${y(q.p.score ?? 0).toFixed(1)}`).join(" ");
            const first = pts[0];
            const prev = si > 0 ? drawn[si - 1] : undefined;
            const prevLast = prev ? prev.pts[prev.pts.length - 1] : undefined;
            const breakX = first && prevLast ? (x(first.i) + x(prevLast.i)) / 2 : null;
            return (
              <g key={`${seg.key}-${si}`}>
                {breakX !== null && (
                  <g>
                    <line x1={breakX} x2={breakX} y1={pad.t - 6} y2={H - pad.b} className="history-break" />
                    <text x={breakX} y={pad.t - 12} textAnchor="middle" className="history-break-label">
                      policy changed
                    </text>
                  </g>
                )}
                {scored.length > 1 && <path d={path} className="history-line" fill="none" />}
                {pts.map(({ p, i }) => {
                  const cx = x(i);
                  const cy = p.score === null ? y(0) : y(p.score);
                  const tip = `${absoluteTime(p.received_at)} · ${p.score === null ? "no score" : `${p.score}/100`} · ${decisionName(p.decision)} · profile ${p.profile} · ${seg.policy} · ${shortCommit(p.commit_sha)}`;
                  return (
                    <g key={p.id}>
                      <title>{tip}</title>
                      {p.score === null ? (
                        <rect x={cx - 4} y={cy - 4} width={8} height={8} className="history-dot history-dot-null" />
                      ) : (
                        <circle cx={cx} cy={cy} r={i === total - 1 ? 6 : 4.5} className={`history-dot${i === total - 1 ? " history-dot-last" : ""}`} />
                      )}
                      {p.score !== null && (
                        <text x={cx} y={cy - 11} textAnchor="middle" className="history-value">
                          {p.score}
                        </text>
                      )}
                      {(i % labelEvery === 0 || i === total - 1) && (
                        <text
                          x={cx}
                          y={H - 12}
                          textAnchor={total > 1 && i === total - 1 ? "end" : total > 1 && i === 0 ? "start" : "middle"}
                          className="history-axis"
                        >
                          {shortDate(p.received_at)}
                        </text>
                      )}
                    </g>
                  );
                })}
              </g>
            );
          })}
        </svg>
      )}
      {hasBreak && (
        <p className="history-note">
          <strong>Not comparable: policy changed.</strong> A line joins only scans that share the same policy pack,
          policy version, and profile. Do not read a trend across a break.
        </p>
      )}
      {!hasBreak && total === 1 && <p className="history-note">One scan so far. A trend appears after the next upload.</p>}
    </div>
  );
}
