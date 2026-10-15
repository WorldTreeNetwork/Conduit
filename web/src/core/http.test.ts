import { describe, expect, it } from "vitest";
import { ManualClock, flushMicrotasks } from "./clock";
import { ConnectionError, MatrixError, describeError } from "./errors";
import { HttpClient, enc } from "./http";
import { FakeServer } from "./testing";

function setup() {
  const server = new FakeServer();
  const clock = new ManualClock();
  const http = new HttpClient({ baseUrl: "https://hs.test/", accessToken: "tok", transport: server.transport, clock });
  return { server, clock, http };
}

describe("HttpClient", () => {
  it("sends bearer auth and JSON, strips trailing slashes from the base URL", async () => {
    const { server, http } = setup();
    server.on("POST", /\/echo$/, (req) => ({ body: { got: req.json } }));
    const result = await http.request<{ got: unknown }>("POST", "/echo", { body: { a: 1 } });
    expect(result.got).toEqual({ a: 1 });
    expect(server.requests[0]!.url).toBe("https://hs.test/echo");
    expect(server.requests[0]!.headers.Authorization).toBe("Bearer tok");
    expect(server.requests[0]!.headers["Content-Type"]).toBe("application/json");
  });

  it("omits the token when auth is false and encodes query params", async () => {
    const { server, http } = setup();
    server.on("GET", /\/q$/, { body: {} });
    await http.request("GET", "/q", { auth: false, query: { since: "s1 2", timeout: 0, skip: undefined } });
    expect(server.requests[0]!.headers.Authorization).toBeUndefined();
    expect(server.requests[0]!.url).toBe("https://hs.test/q?since=s1+2&timeout=0");
  });

  it("parses Matrix errors with errcode, message and status", async () => {
    const { server, http } = setup();
    server.on("GET", /\/x$/, { status: 403, body: { errcode: "M_FORBIDDEN", error: "nope" } });
    const error = (await http.request("GET", "/x").catch((e) => e)) as MatrixError;
    expect(error).toBeInstanceOf(MatrixError);
    expect(error.errcode).toBe("M_FORBIDDEN");
    expect(error.httpStatus).toBe(403);
    expect(error.message).toBe("nope");
    expect(server.requests).toHaveLength(1);
  });

  it("synthesizes an errcode for non-JSON error bodies", async () => {
    const { server, http } = setup();
    server.on("GET", /\/x$/, { status: 502 });
    const error = (await http.request("GET", "/x", { maxRetries: 0 }).catch((e) => e)) as MatrixError;
    expect(error.errcode).toBe("M_HTTP_502");
    expect(error.isTransient).toBe(true);
  });

  it("honours retry_after_ms on 429 then succeeds", async () => {
    const { server, http, clock } = setup();
    server.once("GET", /\/r$/, { status: 429, body: { errcode: "M_LIMIT_EXCEEDED", retry_after_ms: 2500 } });
    server.on("GET", /\/r$/, { body: { ok: true } });
    const pending = http.request<{ ok: boolean }>("GET", "/r");
    await flushMicrotasks();
    expect(server.requests).toHaveLength(1);
    await clock.advance(2499);
    expect(server.requests).toHaveLength(1);
    await clock.advance(1);
    expect(await pending).toEqual({ ok: true });
    expect(server.requests).toHaveLength(2);
  });

  it("prefers the Retry-After header (seconds) over the body field", async () => {
    const { server, http, clock } = setup();
    server.once("GET", /\/r$/, {
      status: 429,
      headers: { "Retry-After": "3" },
      body: { errcode: "M_LIMIT_EXCEEDED", retry_after_ms: 10 },
    });
    server.on("GET", /\/r$/, { body: {} });
    const pending = http.request("GET", "/r");
    await flushMicrotasks();
    await clock.advance(2999);
    expect(server.requests).toHaveLength(1);
    await clock.advance(1);
    await pending;
    expect(server.requests).toHaveLength(2);
  });

  it("backs off exponentially on network errors and gives up after maxRetries", async () => {
    const { server, http, clock } = setup();
    server.on("GET", /\/n$/, { networkError: true });
    const pending = http.request("GET", "/n", { maxRetries: 2 }).catch((e) => e);
    await flushMicrotasks();
    expect(server.requests).toHaveLength(1);
    await clock.advance(500);
    expect(server.requests).toHaveLength(2);
    await clock.advance(999);
    expect(server.requests).toHaveLength(2);
    await clock.advance(1);
    const error = await pending;
    expect(server.requests).toHaveLength(3);
    expect(error).toBeInstanceOf(ConnectionError);
  });

  it("reports M_UNKNOWN_TOKEN to the session owner", async () => {
    const { server, http } = setup();
    let seen: MatrixError | undefined;
    http.onUnknownToken = (e) => (seen = e);
    server.on("GET", /\/w$/, { status: 401, body: { errcode: "M_UNKNOWN_TOKEN", error: "bad", soft_logout: true } });
    await http.request("GET", "/w").catch(() => undefined);
    expect(seen?.isSoftLogout).toBe(true);
  });

  it("encodes room ids as single path segments", () => {
    expect(enc("!room:server.test")).toBe("!room%3Aserver.test");
    expect(enc("#a/b:c")).toBe("%23a%2Fb%3Ac");
  });

  it("describes errors in plain language", () => {
    expect(describeError(new MatrixError(400, { errcode: "M_USER_IN_USE" }))).toMatch(/taken/);
    expect(describeError(new ConnectionError("x"))).toMatch(/reach the server/);
  });
});
