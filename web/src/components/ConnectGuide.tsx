// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { CreatedToken, Project, ProjectOverview } from "../api/types";
import { useAuth } from "../auth";
import { useAsync } from "../lib/useAsync";
import { CreateProjectForm, CreateTokenForm, errorText, TokenReveal } from "./forms";
import { IconArrowRight, IconCheck, IconRefresh } from "./Icons";
import { CodeBlock, ErrorState, Notice, Skeleton, Time } from "./ui";

const TOKEN_PLACEHOLDER = "<paste-your-token>";

export function scanCommands(origin: string): { powershell: string; bash: string } {
  return {
    powershell: `$env:AGENTGOV_TOKEN = "${TOKEN_PLACEHOLDER}"\nagentgov scan . --upload-url ${origin}`,
    bash: `export AGENTGOV_TOKEN="${TOKEN_PLACEHOLDER}"\nagentgov scan . --upload-url ${origin}`,
  };
}

function canManage(p: Project | undefined): boolean {
  return p?.role === "administrator" || p?.role === "owner";
}

type Check =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "waiting"; at: Date }
  | { state: "connected"; overview: ProjectOverview }
  | { state: "error"; message: string };

/**
 * Step-by-step guide to the first upload: project, token, scan command, and
 * a connection check that asks the API whether a scan has arrived.
 */
export function ConnectGuide({ initialProjectId, onConnected }: { initialProjectId?: string; onConnected?: () => void }) {
  const { isAdmin } = useAuth();
  const projects = useAsync((signal) => api.projects(signal), []);
  const [selected, setSelected] = useState(initialProjectId ?? "");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [tokenMade, setTokenMade] = useState(false);
  const [check, setCheck] = useState<Check>({ state: "idle" });

  const list = projects.status === "ready" ? projects.data : [];
  useEffect(() => {
    if (!selected && list[0]) setSelected(list[0].id);
  }, [list, selected]);
  const project = list.find((p) => p.id === selected);
  const cmds = scanCommands(window.location.origin);

  const runCheck = async () => {
    if (!project) return;
    setCheck({ state: "checking" });
    try {
      const d = await api.project(project.id);
      if (d.overview.scan_count > 0) {
        setCheck({ state: "connected", overview: d.overview });
        onConnected?.();
      } else {
        setCheck({ state: "waiting", at: new Date() });
      }
    } catch (err) {
      setCheck({ state: "error", message: errorText(err) });
    }
  };

  if (projects.status === "loading") return <Skeleton lines={6} />;
  if (projects.status === "error") return <ErrorState error={projects.error} onRetry={() => projects.reload()} />;

  return (
    <ol className="guide">
      <li className={`guide-step${project ? " done" : ""}`}>
        <div className="guide-num" aria-hidden="true">
          {project ? <IconCheck size={18} /> : 1}
        </div>
        <div className="guide-body">
          <h3>Choose a project</h3>
          <p>A project groups the agents of one repository or one team. Scans upload into a project.</p>
          {list.length > 0 && (
            <div className="field field-narrow">
              <label htmlFor="guide-project">Project</label>
              <select
                id="guide-project"
                value={selected}
                onChange={(e) => {
                  setSelected(e.target.value);
                  setCreated(null);
                  setTokenMade(false);
                  setCheck({ state: "idle" });
                }}
              >
                {list.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          )}
          {isAdmin ? (
            <details className="disclosure" open={list.length === 0}>
              <summary>Create a new project</summary>
              <CreateProjectForm
                onCreated={(p) => {
                  setSelected(p.id);
                  setCreated(null);
                  setTokenMade(false);
                  setCheck({ state: "idle" });
                  projects.reload(true);
                }}
              />
            </details>
          ) : (
            list.length === 0 && (
              <Notice tone="info" title="You are not a member of any project yet">
                Only an administrator can create a project. Ask an administrator to create one and to add you as an
                owner.
              </Notice>
            )
          )}
        </div>
      </li>

      <li className={`guide-step${tokenMade ? " done" : ""}`}>
        <div className="guide-num" aria-hidden="true">
          {tokenMade ? <IconCheck size={18} /> : 2}
        </div>
        <div className="guide-body">
          <h3>Create an upload token</h3>
          <p>The scanner uses the token to send results to this project. The token cannot read anything.</p>
          {!project ? (
            <p className="muted">Choose a project first.</p>
          ) : !canManage(project) ? (
            <Notice tone="info" title="Your role cannot create tokens">
              Only a project owner or an administrator can create a token. Ask one of them for a token for “
              {project.name}”.
            </Notice>
          ) : created ? (
            <TokenReveal created={created} onDismiss={() => setCreated(null)} />
          ) : (
            <>
              {tokenMade && <p className="ok-line">A token was created. Create another one if you did not save it.</p>}
              <CreateTokenForm
                projectId={project.id}
                onCreated={(t) => {
                  setCreated(t);
                  setTokenMade(true);
                }}
              />
            </>
          )}
        </div>
      </li>

      <li className="guide-step">
        <div className="guide-num" aria-hidden="true">
          3
        </div>
        <div className="guide-body">
          <h3>Run a scan in your repository</h3>
          <p>
            Open a terminal in the repository. Replace the placeholder with the token from step 2, then run the two
            lines. The scan reads files only: it does not run your code and it sends nothing except the result.
          </p>
          <div className="code-pair">
            <CodeBlock label="PowerShell (Windows)" code={cmds.powershell} />
            <CodeBlock label="Bash (Linux, macOS)" code={cmds.bash} />
          </div>
          <p className="muted">
            In a CI system, store the token as a secret and pass it in the <code>AGENTGOV_TOKEN</code> environment
            variable.
          </p>
        </div>
      </li>

      <li className={`guide-step${check.state === "connected" ? " done" : ""}`}>
        <div className="guide-num" aria-hidden="true">
          {check.state === "connected" ? <IconCheck size={18} /> : 4}
        </div>
        <div className="guide-body">
          <h3>Check the connection</h3>
          <p>After the scan finishes, ask the server whether the result arrived.</p>
          <button type="button" className="btn btn-primary" onClick={() => void runCheck()} disabled={!project || check.state === "checking"}>
            <IconRefresh size={16} />
            {check.state === "checking" ? "Checking…" : "Check connection"}
          </button>
          <div aria-live="polite" className="guide-result">
            {check.state === "connected" && project && (
              <Notice tone="success" title="Connected. The first scan arrived.">
                <p>
                  “{project.name}” has {check.overview.scan_count} {check.overview.scan_count === 1 ? "scan" : "scans"} and{" "}
                  {check.overview.agent_count} {check.overview.agent_count === 1 ? "agent" : "agents"}. Latest upload:{" "}
                  <Time value={check.overview.latest_scan_at} />.
                </p>
                <p>
                  <Link to={`/projects/${project.id}`} className="btn">
                    Open the project
                    <IconArrowRight size={16} />
                  </Link>
                </p>
              </Notice>
            )}
            {check.state === "waiting" && (
              <Notice tone="warn" title="No scan has arrived yet">
                The server has no scan for this project (checked at {check.at.toLocaleTimeString()}). Check that the
                command finished without an error, that the token belongs to this project, and that the upload address
                is {window.location.origin}.
              </Notice>
            )}
            {check.state === "error" && <Notice tone="danger">{check.message}</Notice>}
          </div>
        </div>
      </li>
    </ol>
  );
}
