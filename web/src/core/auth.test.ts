import { describe, expect, it } from "vitest";
import { register, loginWithPassword, UnsupportedAuthError, validateUsername, withUia } from "./auth";
import { ManualClock } from "./clock";
import { MatrixError } from "./errors";
import { HttpClient } from "./http";
import { FakeServer } from "./testing";
import { discoverHomeserver } from "./discovery";

function setup() {
  const server = new FakeServer();
  const clock = new ManualClock();
  const http = new HttpClient({ baseUrl: "https://hs.test", transport: server.transport, clock });
  return { server, clock, http };
}

describe("registration with UIA", () => {
  it("completes the m.login.dummy stage using the server's session", async () => {
    const { server, http } = setup();
    server.on("POST", /\/register$/, (req) => {
      const body = req.json as { auth?: { type: string; session: string } };
      if (!body.auth) {
        return { status: 401, body: { flows: [{ stages: ["m.login.dummy"] }], session: "S1", params: {} } };
      }
      expect(body.auth).toEqual({ type: "m.login.dummy", session: "S1" });
      return { body: { user_id: "@ann:hs.test", access_token: "T", device_id: "D" } };
    });
    const session = await register(http, " ann ", "pw");
    expect(session).toEqual({ homeserverUrl: "https://hs.test", userId: "@ann:hs.test", accessToken: "T", deviceId: "D" });
    expect(server.requests).toHaveLength(2);
    expect((server.requests[0]!.json as { username: string }).username).toBe("ann");
    expect(server.requests[0]!.query.get("kind")).toBe("user");
  });

  it("refuses flows it cannot complete with a clear error", async () => {
    const { server, http } = setup();
    server.on("POST", /\/register$/, {
      status: 401,
      body: { flows: [{ stages: ["m.login.recaptcha", "m.login.terms"] }], session: "S" },
    });
    const error = await register(http, "ann", "pw").catch((e) => e);
    expect(error).toBeInstanceOf(UnsupportedAuthError);
    expect(error.message).toMatch(/m.login.recaptcha/);
  });

  it("surfaces M_USER_IN_USE without retrying", async () => {
    const { server, http } = setup();
    server.on("POST", /\/register$/, { status: 400, body: { errcode: "M_USER_IN_USE", error: "taken" } });
    const error = await register(http, "ann", "pw").catch((e) => e);
    expect(error).toBeInstanceOf(MatrixError);
    expect(error.errcode).toBe("M_USER_IN_USE");
    expect(server.requests).toHaveLength(1);
  });

  it("completes a password stage when credentials are supplied", async () => {
    let calls = 0;
    const result = await withUia(
      async (auth) => {
        calls++;
        if (!auth) {
          throw new MatrixError(401, { flows: [{ stages: ["m.login.password"] }], session: "P" });
        }
        expect(auth).toMatchObject({ type: "m.login.password", session: "P", password: "pw" });
        return "done";
      },
      { userId: "@ann:hs.test", password: "pw" },
    );
    expect(result).toBe("done");
    expect(calls).toBe(2);
  });
});

describe("password login", () => {
  it("uses the m.id.user identifier and honours a well_known override", async () => {
    const { server, http } = setup();
    server.on("POST", /\/login$/, {
      body: {
        user_id: "@ann:hs.test",
        access_token: "T",
        device_id: "D",
        well_known: { "m.homeserver": { base_url: "https://matrix.hs.test/" } },
      },
    });
    const session = await loginWithPassword(http, "ann", "pw");
    expect(server.requests[0]!.json).toMatchObject({
      type: "m.login.password",
      identifier: { type: "m.id.user", user: "ann" },
      password: "pw",
    });
    expect(session.homeserverUrl).toBe("https://matrix.hs.test");
  });

  it("propagates M_FORBIDDEN for bad credentials", async () => {
    const { server, http } = setup();
    server.on("POST", /\/login$/, { status: 403, body: { errcode: "M_FORBIDDEN", error: "Invalid password" } });
    const error = await loginWithPassword(http, "ann", "bad").catch((e) => e);
    expect(error.errcode).toBe("M_FORBIDDEN");
  });
});

describe("validateUsername", () => {
  it("accepts the localpart grammar and rejects the rest", () => {
    expect(validateUsername("alice.b-1")).toBeUndefined();
    expect(validateUsername("")).toBeDefined();
    expect(validateUsername("Alice")).toBeDefined();
    expect(validateUsername("a b")).toBeDefined();
  });
});

describe("homeserver discovery", () => {
  it("uses a full URL directly after checking /versions", async () => {
    const server = new FakeServer();
    server.on("GET", /\/_matrix\/client\/versions$/, { body: { versions: ["v1.11"] } });
    const result = await discoverHomeserver("http://127.0.0.1:8008/", { transport: server.transport, clock: new ManualClock() });
    expect(result).toEqual({ kind: "ok", baseUrl: "http://127.0.0.1:8008", versions: ["v1.11"] });
  });

  it("follows .well-known for a server name taken from a Matrix ID", async () => {
    const server = new FakeServer();
    server.on("GET", /\/.well-known\/matrix\/client$/, {
      body: { "m.homeserver": { base_url: "https://matrix.example.org" } },
    });
    server.on("GET", /\/_matrix\/client\/versions$/, { body: { versions: ["v1.11"] } });
    const result = await discoverHomeserver("@me:example.org", { transport: server.transport, clock: new ManualClock() });
    expect(result).toMatchObject({ kind: "ok", baseUrl: "https://matrix.example.org" });
    expect(server.requests[0]!.url).toBe("https://example.org/.well-known/matrix/client");
  });

  it("IGNOREs a 404 well-known and falls back to the server name", async () => {
    const server = new FakeServer();
    server.on("GET", /\/.well-known\/matrix\/client$/, { status: 404, body: {} });
    server.on("GET", /\/_matrix\/client\/versions$/, { body: { versions: ["v1.1"] } });
    const result = await discoverHomeserver("example.org", { transport: server.transport, clock: new ManualClock() });
    expect(result).toMatchObject({ kind: "ok", baseUrl: "https://example.org" });
  });

  it("FAIL_PROMPTs on a well-known without m.homeserver", async () => {
    const server = new FakeServer();
    server.on("GET", /\/.well-known\/matrix\/client$/, { body: { other: 1 } });
    const result = await discoverHomeserver("example.org", { transport: server.transport, clock: new ManualClock() });
    expect(result.kind).toBe("prompt");
  });

  it("FAIL_ERRORs when the advertised server is not a homeserver", async () => {
    const server = new FakeServer();
    server.on("GET", /\/_matrix\/client\/versions$/, { body: { nothing: true } });
    const result = await discoverHomeserver("https://not-matrix.test", { transport: server.transport, clock: new ManualClock() });
    expect(result.kind).toBe("error");
  });
});
