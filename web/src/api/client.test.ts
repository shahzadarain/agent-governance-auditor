// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, setCsrfToken, setUnauthorizedHandler } from "./client";

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

describe("api client", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    setCsrfToken("");
    setUnauthorizedHandler(null);
    window.localStorage.clear();
    window.sessionStorage.clear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("sends the cookie on same-origin requests and no CSRF token on reads", async () => {
    setCsrfToken("csrf-123");
    fetchMock.mockResolvedValue(respond(200, { items: [] }));
    await api.projects();
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/v1/projects");
    expect(init?.credentials).toBe("same-origin");
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("sends the CSRF token on mutating requests", async () => {
    setCsrfToken("csrf-123");
    fetchMock.mockResolvedValue(respond(201, { token: "agt_x", record: {} }));
    await api.createToken("prj_1", "ci", 90);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/v1/projects/prj_1/tokens");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-123");
    expect(JSON.parse(String(init?.body))).toEqual({ name: "ci", expires_in_days: 90 });
  });

  it("keeps nothing in browser storage", async () => {
    fetchMock.mockResolvedValue(
      respond(200, { user: { id: "u", username: "a", role: "administrator" }, csrf_token: "secret-csrf", expires_at: "", idle_expires_at: "" }),
    );
    const s = await api.login("a", "a-long-password");
    setCsrfToken(s.csrf_token);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("turns an error body into one ApiError", async () => {
    fetchMock.mockResolvedValue(respond(404, { error: { code: "not_found", message: "The requested resource does not exist." } }));
    const err = await api.agent("nope").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 404, code: "not_found", message: "The requested resource does not exist.", isNotFound: true });
  });

  it("calls the unauthorized handler on 401, except for sign-in itself", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    fetchMock.mockImplementation(async () => respond(401, { error: { code: "unauthenticated", message: "Sign in to continue." } }));
    await expect(api.overview()).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    await expect(api.login("a", "b")).rejects.toMatchObject({ status: 401 });
    await expect(api.session()).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("reads Retry-After on 429", async () => {
    fetchMock.mockResolvedValue(respond(429, { error: { code: "rate_limited", message: "Too many sign-in attempts. Retry later." } }, { "Retry-After": "31" }));
    await expect(api.login("a", "b")).rejects.toMatchObject({ status: 429, retryAfter: 31, isRateLimited: true });
  });

  it("reports a network failure and a non-JSON body as errors", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("failed to fetch"));
    await expect(api.version()).rejects.toMatchObject({ status: 0, code: "network_error" });
    fetchMock.mockResolvedValueOnce(new Response("<html>", { status: 200 }));
    await expect(api.version()).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("encodes path segments and drops empty filters", async () => {
    fetchMock.mockResolvedValue(respond(200, { items: [], total: 0, limit: 1000, offset: 0 }));
    await api.scanFindings("scn/1", { severity: "critical", control_id: "", agent_id: "a b" });
    expect(fetchMock.mock.calls[0]![0]).toBe("/api/v1/scans/scn%2F1/findings?severity=critical&agent_id=a+b&limit=1000");
  });
});
