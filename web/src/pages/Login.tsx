// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth";
import { AuthLayout } from "../components/AuthLayout";
import { PasswordInput } from "../components/forms";
import { Field, Notice } from "../components/ui";

/** Every credential failure gets the same generic text. */
export function loginErrorText(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.isRateLimited) {
      return err.retryAfter
        ? `Too many sign-in attempts. Wait ${err.retryAfter} seconds, then try again.`
        : "Too many sign-in attempts. Wait a moment, then try again.";
    }
    if (err.status === 401) return "The username or the password is not correct.";
    if (err.status === 0) return err.message;
  }
  return "Sign-in did not work. Try again.";
}

export function Login() {
  const { signIn, expired } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      signIn(await api.login(username, password));
    } catch (err) {
      setError(loginErrorText(err));
      setPassword("");
      setBusy(false);
    }
  };

  return (
    <AuthLayout title="Sign in" lead="Use the account that your administrator created for you.">
      {expired && !error && (
        <Notice tone="info" title="Your session ended">
          Sessions end after 12 hours, or after 2 hours without activity. Sign in again to continue.
        </Notice>
      )}
      <form onSubmit={submit} className="form-stack">
        <Field label="Username">
          {({ id }) => (
            <input
              id={id}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              autoFocus
            />
          )}
        </Field>
        <Field label="Password">
          {({ id }) => <PasswordInput id={id} value={password} onChange={setPassword} autoComplete="current-password" />}
        </Field>
        <div aria-live="assertive">{error && <Notice tone="danger">{error}</Notice>}</div>
        <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="muted small">There is no password reset by email. An administrator can create a new account for you.</p>
    </AuthLayout>
  );
}
