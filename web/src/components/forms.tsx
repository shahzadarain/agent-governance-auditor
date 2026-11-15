// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { CreatedToken, Project } from "../api/types";
import { IconClose, IconEye, IconEyeOff, IconLock } from "./Icons";
import { CopyButton, Field, Notice } from "./ui";

export function errorText(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.isRateLimited) {
      return err.retryAfter
        ? `Too many attempts. Wait ${err.retryAfter} seconds and try again.`
        : "Too many attempts. Wait a moment and try again.";
    }
    return err.message;
  }
  return "Something went wrong. Try again.";
}

export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/, "");
}

export function PasswordInput({
  id,
  value,
  onChange,
  describedBy,
  autoComplete,
  minLength,
  what = "password",
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  describedBy?: string;
  autoComplete: string;
  minLength?: number;
  /** Names the value in the show and hide button, for example "bootstrap token". */
  what?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="input-group">
      <input
        id={id}
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-describedby={describedBy}
        autoComplete={autoComplete}
        minLength={minLength}
        required
        spellCheck={false}
        autoCapitalize="none"
      />
      <button
        type="button"
        className="icon-btn input-addon"
        onClick={() => setShow((s) => !s)}
        aria-label={show ? `Hide ${what}` : `Show ${what}`}
        aria-pressed={show}
      >
        {show ? <IconEyeOff size={18} /> : <IconEye size={18} />}
      </button>
    </div>
  );
}

export function CreateProjectForm({ onCreated }: { onCreated: (p: Project) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const effectiveSlug = slugTouched ? slug : slugify(name);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const p = await api.createProject(effectiveSlug, name.trim());
      setName("");
      setSlug("");
      setSlugTouched(false);
      onCreated(p);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="form-inline" aria-label="Create a project">
      <Field label="Project name" hint="For example the name of the product or the team.">
        {({ id, describedBy }) => (
          <input id={id} value={name} onChange={(e) => setName(e.target.value)} aria-describedby={describedBy} maxLength={200} required />
        )}
      </Field>
      <Field label="Short ID" hint="Lower-case letters, digits, and hyphens. Used in links.">
        {({ id, describedBy }) => (
          <input
            id={id}
            value={effectiveSlug}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value);
            }}
            aria-describedby={describedBy}
            pattern="[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?"
            maxLength={64}
            required
            spellCheck={false}
            autoCapitalize="none"
          />
        )}
      </Field>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Creating…" : "Create project"}
        </button>
      </div>
      {error && (
        <div className="form-wide">
          <Notice tone="danger">{error}</Notice>
        </div>
      )}
    </form>
  );
}

export function CreateTokenForm({ projectId, onCreated }: { projectId: string; onCreated: (t: CreatedToken) => void }) {
  const [name, setName] = useState("ci-upload");
  const [days, setDays] = useState("90");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onCreated(await api.createToken(projectId, name.trim(), Number(days)));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="form-inline" aria-label="Create an upload token">
      <Field label="Token name" hint="Say where the token is used, for example the CI system.">
        {({ id, describedBy }) => (
          <input id={id} value={name} onChange={(e) => setName(e.target.value)} aria-describedby={describedBy} maxLength={100} required />
        )}
      </Field>
      <Field label="Expires after" hint="A token can only upload scans to this project.">
        {({ id, describedBy }) => (
          <select id={id} value={days} onChange={(e) => setDays(e.target.value)} aria-describedby={describedBy}>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="180">180 days</option>
            <option value="365">365 days</option>
            <option value="0">No expiry</option>
          </select>
        )}
      </Field>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Creating…" : "Create token"}
        </button>
      </div>
      {error && (
        <div className="form-wide">
          <Notice tone="danger">{error}</Notice>
        </div>
      )}
    </form>
  );
}

/** Shows a new token once. The value lives in component state only. */
export function TokenReveal({ created, onDismiss }: { created: CreatedToken; onDismiss: () => void }) {
  return (
    <div className="token-reveal" role="status" data-testid="token-reveal">
      <div className="token-reveal-head">
        <IconLock size={18} />
        <strong>Copy this token now</strong>
        <button type="button" className="icon-btn" onClick={onDismiss} aria-label="Dismiss the token panel">
          <IconClose size={18} />
        </button>
      </div>
      <p>
        This is the only time the token “{created.record.name}” is shown. The server stores only a hash, so it cannot
        show the token again. Keep it in a secret store, not in a file in the repository.
      </p>
      <div className="token-value">
        <code data-testid="token-value">{created.token}</code>
        <CopyButton text={created.token} label="Copy token" />
      </div>
      <button type="button" className="btn" onClick={onDismiss}>
        I have saved it
      </button>
    </div>
  );
}
