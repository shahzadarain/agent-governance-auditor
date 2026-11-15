// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth";
import { AuthLayout } from "../components/AuthLayout";
import { errorText, PasswordInput } from "../components/forms";
import { Field, Notice } from "../components/ui";

export const MIN_PASSWORD = 12;

export function Setup() {
  const { signIn, setupDone } = useAuth();
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const chars = [...password].length;
  const longEnough = chars >= MIN_PASSWORD;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!longEnough) {
      setError(`The password must have at least ${MIN_PASSWORD} characters.`);
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.setup(token.trim(), username.trim(), password);
    } catch (err) {
      if (err instanceof ApiError && err.code === "setup_complete") {
        setupDone();
        return;
      }
      setError(errorText(err));
      setBusy(false);
      return;
    }
    // The account exists now. Sign in with the same credentials.
    try {
      signIn(await api.login(username.trim(), password));
    } catch {
      setupDone();
    }
  };

  return (
    <AuthLayout
      title="Set up this server"
      lead="No account exists yet. Create the first administrator. This screen appears only once."
    >
      <form onSubmit={submit} className="form-stack">
        <Field
          label="Bootstrap token"
          hint="The server prints this one-time token in its console (or container log) when it starts, on the line that begins with “Bootstrap token”. It is valid for one hour."
        >
          {({ id, describedBy }) => (
            <PasswordInput id={id} value={token} onChange={setToken} describedBy={describedBy} autoComplete="off" what="bootstrap token" />
          )}
        </Field>
        <Field label="Administrator username" hint="3 to 64 characters: letters, digits, dot, underscore, hyphen, or @.">
          {({ id, describedBy }) => (
            <input
              id={id}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              aria-describedby={describedBy}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              minLength={3}
              maxLength={64}
              required
            />
          )}
        </Field>
        <Field
          label="Password"
          hint={
            <span className={longEnough ? "rule rule-ok" : "rule"}>
              At least {MIN_PASSWORD} characters.
              {chars > 0 && !longEnough ? ` ${MIN_PASSWORD - chars} more to go.` : ""}
              {longEnough ? " Long enough." : ""}
            </span>
          }
        >
          {({ id, describedBy }) => (
            <PasswordInput
              id={id}
              value={password}
              onChange={setPassword}
              describedBy={describedBy}
              autoComplete="new-password"
              minLength={MIN_PASSWORD}
            />
          )}
        </Field>
        <div aria-live="assertive">{error && <Notice tone="danger">{error}</Notice>}</div>
        <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
          {busy ? "Creating the account…" : "Create administrator and sign in"}
        </button>
      </form>
      <p className="muted small">
        The token works once. If it expired, restart the server to print a new one. There is no default user and no
        default password.
      </p>
    </AuthLayout>
  );
}
