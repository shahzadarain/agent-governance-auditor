// SPDX-License-Identifier: Apache-2.0

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { ApiError } from "../api/client";
import type { Async } from "../lib/useAsync";
import { absoluteTime, relativeTime } from "../lib/format";
import {
  decisionKey,
  decisionName,
  rollupOf,
  severityLabel,
  severityRank,
  statusLabel,
  statusMeaning,
} from "../lib/labels";
import {
  DecisionIcon,
  IconCheck,
  IconChevronRight,
  IconCopy,
  IconLock,
  IconRefresh,
  IconSearch,
  IconSeverity,
  IconWarning,
  RollupIcon,
} from "./Icons";

// --- Chips --------------------------------------------------------------------

export function DecisionChip({ decision, large }: { decision: string; large?: boolean }) {
  const key = decisionKey(decision);
  return (
    <span className={`chip chip-${key}${large ? " chip-lg" : ""}`}>
      <DecisionIcon decision={key} size={large ? 18 : 15} />
      {decisionName(decision)}
    </span>
  );
}

export function StatusBadge({ status, withMeaning }: { status: string; withMeaning?: boolean }) {
  const r = rollupOf(status);
  return (
    <span className={`status status-${r}`} title={withMeaning ? undefined : statusMeaning(status)}>
      <RollupIcon rollup={r} size={16} />
      <span>{statusLabel(status)}</span>
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const rank = severityRank(severity);
  const key = rank < 5 ? severity : "unrated";
  return (
    <span className={`sev sev-${key}`}>
      <IconSeverity level={Math.max(0, 4 - rank)} />
      {severityLabel(severity)}
    </span>
  );
}

export function Pill({ children, tone = "neutral", title }: { children: ReactNode; tone?: "neutral" | "info" | "warn"; title?: string }) {
  return (
    <span className={`pill pill-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function MandatoryMark({ min }: { min?: number }) {
  return (
    <span className="mandatory" title={min ? `Mandatory under this profile. Required maturity: ${min} of 4.` : "Mandatory under this profile."}>
      <IconLock size={12} />
      Mandatory
    </span>
  );
}

/** Maturity as four segments plus the text "n/4". */
export function MaturityBar({ value, required }: { value: number; required?: number }) {
  const v = Math.max(0, Math.min(4, value));
  const label = `Maturity ${v} of 4${required ? `, required ${required}` : ""}`;
  return (
    <span className="maturity" role="img" aria-label={label} title={label}>
      <span className="maturity-segs" aria-hidden="true">
        {[1, 2, 3, 4].map((i) => (
          <span key={i} className={`maturity-seg${i <= v ? " on" : ""}${required === i ? " req" : ""}`} />
        ))}
      </span>
      <span className="maturity-num" aria-hidden="true">
        {v}/4
      </span>
    </span>
  );
}

// --- Time ---------------------------------------------------------------------

export function Time({ value, fallback = "Never" }: { value: string | null | undefined; fallback?: string }) {
  if (!value) return <span className="muted">{fallback}</span>;
  const abs = absoluteTime(value);
  if (!abs) return <span className="muted">{fallback}</span>;
  return (
    <time dateTime={value} title={abs}>
      {relativeTime(value)}
    </time>
  );
}

// --- Layout pieces ------------------------------------------------------------

export interface Crumb {
  label: string;
  to?: string;
}

export function PageHeader({
  title,
  lead,
  crumbs,
  actions,
  eyebrow,
}: {
  title: string;
  lead?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
  eyebrow?: ReactNode;
}) {
  useEffect(() => {
    document.title = `${title} · AgentGov Auditor`;
  }, [title]);
  return (
    <header className="page-header">
      {crumbs && crumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="crumbs">
          <ol>
            {crumbs.map((c, i) => (
              <li key={`${c.label}-${i}`}>
                {i > 0 && <IconChevronRight size={14} />}
                {c.to ? <Link to={c.to}>{c.label}</Link> : <span aria-current="page">{c.label}</span>}
              </li>
            ))}
          </ol>
        </nav>
      )}
      <div className="page-header-row">
        <div className="page-header-text">
          {eyebrow && <div className="eyebrow">{eyebrow}</div>}
          <h1>{title}</h1>
          {lead && <p className="lead">{lead}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
    </header>
  );
}

export function Card({
  title,
  children,
  actions,
  className,
  note,
  flush,
  id,
}: {
  title?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
  note?: ReactNode;
  flush?: boolean;
  id?: string;
}) {
  const hid = useId();
  return (
    <section className={`card${flush ? " card-flush" : ""}${className ? ` ${className}` : ""}`} aria-labelledby={title ? hid : undefined} id={id}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h2 id={hid}>{title}</h2>}
            {note && <p className="card-note">{note}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Skeleton({ lines = 3, height }: { lines?: number; height?: number }) {
  if (height) return <div className="skeleton skeleton-block" style={{ height }} aria-hidden="true" />;
  return (
    <div className="skeleton-lines" aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton skeleton-line" style={{ width: `${92 - ((i * 17) % 40)}%` }} />
      ))}
    </div>
  );
}

export function LoadingPage({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="loading-page">
      <span className="sr-only">{label}…</span>
      <div className="skeleton skeleton-title" aria-hidden="true" />
      <div className="skeleton-grid" aria-hidden="true">
        <div className="skeleton skeleton-block" style={{ height: 120 }} />
        <div className="skeleton skeleton-block" style={{ height: 120 }} />
        <div className="skeleton skeleton-block" style={{ height: 120 }} />
      </div>
      <div className="skeleton skeleton-block" style={{ height: 260 }} aria-hidden="true" />
    </div>
  );
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="empty-icon">{icon}</div>}
      <h3>{title}</h3>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function Notice({
  tone,
  title,
  children,
  icon,
}: {
  tone: "info" | "warn" | "danger" | "success";
  title?: string;
  children?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className={`notice notice-${tone}`} role={tone === "danger" ? "alert" : "status"}>
      <span className="notice-icon">{icon ?? (tone === "success" ? <IconCheck size={18} /> : <IconWarning size={18} />)}</span>
      <div>
        {title && <p className="notice-title">{title}</p>}
        {children && <div className="notice-body">{children}</div>}
      </div>
    </div>
  );
}

/** Explains a failed request. 404 means missing or not permitted: the server does not say which. */
export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  if (error.isNotFound) {
    return (
      <div className="empty" role="alert">
        <div className="empty-icon">
          <IconSearch size={28} />
        </div>
        <h3>Not found, or you do not have access</h3>
        <div className="empty-body">
          <p>
            This item does not exist, or your account is not a member of its project. The server gives the same answer
            in both cases. Ask a project owner or an administrator for access.
          </p>
          <p>
            <Link to="/" className="btn">
              Go to the overview
            </Link>
          </p>
        </div>
      </div>
    );
  }
  if (error.isForbidden) {
    return (
      <div className="empty" role="alert">
        <div className="empty-icon">
          <IconLock size={28} />
        </div>
        <h3>You do not have permission to see this</h3>
        <div className="empty-body">
          <p>Your role does not allow this view. Ask a project owner or an administrator.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="empty" role="alert">
      <div className="empty-icon empty-icon-danger">
        <IconWarning size={28} />
      </div>
      <h3>This did not load</h3>
      <div className="empty-body">
        <p>{error.message}</p>
        {onRetry && (
          <p>
            <button type="button" className="btn" onClick={onRetry}>
              <IconRefresh size={16} />
              Try again
            </button>
          </p>
        )}
      </div>
    </div>
  );
}

/** Renders loading, error, or the ready content of one request. */
export function AsyncView<T>({
  state,
  children,
  loading,
}: {
  state: Async<T>;
  children: (data: T) => ReactNode;
  loading?: ReactNode;
}) {
  if (state.status === "loading") {
    return (
      loading ?? (
        <div role="status" aria-live="polite">
          <span className="sr-only">Loading…</span>
          <Skeleton lines={4} />
        </div>
      )
    );
  }
  if (state.status === "error") return <ErrorState error={state.error} onRetry={() => state.reload()} />;
  return <>{children(state.data)}</>;
}

// --- Copy ---------------------------------------------------------------------

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to the selection method.
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <button
      type="button"
      className="btn btn-small"
      onClick={async () => {
        const ok = await copyText(text);
        setState(ok ? "copied" : "failed");
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setState("idle"), 2500);
      }}
    >
      {state === "copied" ? <IconCheck size={15} /> : <IconCopy size={15} />}
      <span aria-live="polite">
        {state === "copied" ? "Copied" : state === "failed" ? "Select and copy by hand" : label}
      </span>
    </button>
  );
}

export function CodeBlock({ code, label }: { code: string; label: string }) {
  return (
    <div className="codeblock">
      <div className="codeblock-head">
        <span>{label}</span>
        <CopyButton text={code} label="Copy" />
      </div>
      <pre tabIndex={0} aria-label={`${label} command`}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

// --- Small helpers ------------------------------------------------------------

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Meter({ label, percent, hint }: { label: string; percent: number; hint: string }) {
  const p = Math.max(0, Math.min(100, percent));
  return (
    <div className="meter">
      <div className="meter-top">
        <span className="meter-label">{label}</span>
        <span className="meter-value">{p}%</span>
      </div>
      <div className="meter-track" role="img" aria-label={`${label}: ${p} percent`}>
        <span className="meter-fill" style={{ width: `${p}%` }} />
      </div>
      <p className="meter-hint">{hint}</p>
    </div>
  );
}

export function TextList({ items, ordered, empty }: { items: string[] | null | undefined; ordered?: boolean; empty?: string }) {
  if (!items || items.length === 0) return empty ? <p className="muted">{empty}</p> : null;
  const L = ordered ? "ol" : "ul";
  return (
    <L className={ordered ? "steps" : "bullets"}>
      {items.map((t, i) => (
        <li key={i}>{t}</li>
      ))}
    </L>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: string;
  children: (ids: { id: string; describedBy: string | undefined }) => ReactNode;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = [hint ? hintId : "", error ? errId : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, describedBy })}
      {hint && (
        <p className="field-hint" id={hintId}>
          {hint}
        </p>
      )}
      {error && (
        <p className="field-error" id={errId} role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
