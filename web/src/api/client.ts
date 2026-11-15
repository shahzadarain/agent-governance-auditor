// SPDX-License-Identifier: Apache-2.0
//
// The single API client of the dashboard. Rules:
//   - The session is an HttpOnly cookie; requests use credentials "same-origin".
//   - The CSRF token lives in memory only and is sent on mutating requests.
//   - Nothing here writes to localStorage or sessionStorage.
//   - Every failure becomes one ApiError with {code, message, status}.

import type {
  Agent,
  AgentDetail,
  AgentScan,
  ApiToken,
  AuditEvent,
  Catalog,
  CompareResponse,
  ControlResult,
  CreatedToken,
  Finding,
  Member,
  OverviewResponse,
  Page,
  Profile,
  Project,
  ProjectDetail,
  ScanDetail,
  Session,
  User,
  VersionInfo,
} from "./types";

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  /** Seconds the server asked the client to wait (429 only). */
  readonly retryAfter: number | null;

  constructor(status: number, code: string, message: string, retryAfter: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }
  /** The server answers 404 for missing objects and for objects the user may not see. */
  get isNotFound(): boolean {
    return this.status === 404;
  }
  get isForbidden(): boolean {
    return this.status === 403;
  }
  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

let csrfToken = "";
let onUnauthorized: (() => void) | null = null;

/** Keeps the CSRF token in memory for mutating requests. */
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

/** Registers the handler that runs when a signed-in request answers 401. */
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

interface RequestOptions {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  query?: Record<string, string | number | undefined>;
  /** Login, setup, and the session probe handle 401 themselves. */
  quiet401?: boolean;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (method !== "GET" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body,
      credentials: "same-origin",
      cache: "no-store",
      signal: opts.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(0, "network_error", "The server did not answer. Check that it is running and try again.");
  }

  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const e = (data as { error?: { code?: unknown; message?: unknown } } | null)?.error;
    const code = typeof e?.code === "string" ? e.code : "http_error";
    const message = typeof e?.message === "string" ? e.message : `The server answered with status ${res.status}.`;
    const ra = Number(res.headers.get("Retry-After"));
    const err = new ApiError(res.status, code, message, Number.isFinite(ra) && ra > 0 ? ra : null);
    if (res.status === 401 && !opts.quiet401 && onUnauthorized) onUnauthorized();
    throw err;
  }
  if (data === null) {
    throw new ApiError(res.status, "invalid_response", "The server sent a response that is not valid JSON.");
  }
  return data as T;
}

const enc = encodeURIComponent;

interface Items<T> {
  items: T[] | null;
}
const items = async <T>(p: Promise<Items<T>>): Promise<T[]> => (await p).items ?? [];

export const api = {
  version: (signal?: AbortSignal) => request<VersionInfo>("/api/v1/version", { signal }),

  setup: (bootstrapToken: string, username: string, password: string) =>
    request<{ user: User }>("/api/v1/setup", {
      method: "POST",
      body: { bootstrap_token: bootstrapToken, username, password },
      quiet401: true,
    }),
  login: (username: string, password: string) =>
    request<Session>("/api/v1/login", { method: "POST", body: { username, password }, quiet401: true }),
  logout: () => request<{ status: string }>("/api/v1/logout", { method: "POST", quiet401: true }),
  session: (signal?: AbortSignal) => request<Session>("/api/v1/session", { quiet401: true, signal }),

  overview: (signal?: AbortSignal) => request<OverviewResponse>("/api/v1/overview", { signal }),

  users: (signal?: AbortSignal) => items(request<Items<User>>("/api/v1/users", { signal })),
  createUser: (username: string, password: string, role: string) =>
    request<{ user: User }>("/api/v1/users", { method: "POST", body: { username, password, role } }),

  projects: (signal?: AbortSignal) => items(request<Items<Project>>("/api/v1/projects", { signal })),
  createProject: (slug: string, name: string) =>
    request<Project>("/api/v1/projects", { method: "POST", body: { slug, name } }),
  project: (id: string, signal?: AbortSignal) => request<ProjectDetail>(`/api/v1/projects/${enc(id)}`, { signal }),
  projectAgents: (id: string, signal?: AbortSignal) =>
    items(request<Items<Agent>>(`/api/v1/projects/${enc(id)}/agents`, { signal })),

  tokens: (projectId: string, signal?: AbortSignal) =>
    items(request<Items<ApiToken>>(`/api/v1/projects/${enc(projectId)}/tokens`, { signal })),
  createToken: (projectId: string, name: string, expiresInDays: number) =>
    request<CreatedToken>(`/api/v1/projects/${enc(projectId)}/tokens`, {
      method: "POST",
      body: { name, expires_in_days: expiresInDays },
    }),
  revokeToken: (projectId: string, tokenId: string) =>
    request<{ status: string }>(`/api/v1/projects/${enc(projectId)}/tokens/${enc(tokenId)}`, { method: "DELETE" }),

  members: (projectId: string, signal?: AbortSignal) =>
    items(request<Items<Member>>(`/api/v1/projects/${enc(projectId)}/members`, { signal })),
  setMember: (projectId: string, username: string, role: string) =>
    request<Member>(`/api/v1/projects/${enc(projectId)}/members`, { method: "POST", body: { username, role } }),
  removeMember: (projectId: string, userId: string) =>
    request<{ status: string }>(`/api/v1/projects/${enc(projectId)}/members`, {
      method: "DELETE",
      query: { user_id: userId },
    }),

  agent: (key: string, signal?: AbortSignal) => request<AgentDetail>(`/api/v1/agents/${enc(key)}`, { signal }),
  agentScans: (key: string, signal?: AbortSignal) =>
    items(request<Items<AgentScan>>(`/api/v1/agents/${enc(key)}/scans`, { query: { limit: 200 }, signal })),

  scan: (id: string, signal?: AbortSignal) => request<ScanDetail>(`/api/v1/scans/${enc(id)}`, { signal }),
  scanFindings: (
    id: string,
    filter: { severity?: string; control_id?: string; agent_id?: string } = {},
    signal?: AbortSignal,
  ) => request<Page<Finding>>(`/api/v1/scans/${enc(id)}/findings`, { query: { ...filter, limit: 1000 }, signal }),
  scanControls: (id: string, filter: { agent_id?: string; status?: string; control_id?: string } = {}, signal?: AbortSignal) =>
    request<Page<ControlResult>>(`/api/v1/scans/${enc(id)}/controls`, { query: { ...filter, limit: 1000 }, signal }),
  compare: (afterId: string, beforeId: string, signal?: AbortSignal) =>
    request<CompareResponse>(`/api/v1/scans/${enc(afterId)}/compare/${enc(beforeId)}`, { signal }),

  controls: (signal?: AbortSignal) => request<Catalog>("/api/v1/controls", { signal }),
  policies: async (signal?: AbortSignal) =>
    (await request<{ profiles: Profile[] | null }>("/api/v1/policies", { signal })).profiles ?? [],

  auditEvents: (opts: { project?: string; before?: number; limit?: number }, signal?: AbortSignal) =>
    items(request<Items<AuditEvent>>("/api/v1/audit-events", { query: opts, signal })),
};
