import { describe, expect, it } from "vitest";
import { MatrixClient, loadStoredSession, saveSession } from "./client";
import { ManualClock, flushMicrotasks } from "./clock";
import { MemoryStore, KEYS } from "./store";
import { FakeServer } from "./testing";
import type { Session } from "./types";

const session: Session = {
  homeserverUrl: "https://hs.test",
  userId: "@me:test",
  accessToken: "old",
  deviceId: "DEV",
  refreshToken: "r1",
};

function setup(start: Session = session) {
  const server = new FakeServer();
  const store = new MemoryStore();
  saveSession(store, start);
  const client = new MatrixClient({ session: start, store, transport: server.transport, clock: new ManualClock() });
  return { server, store, client };
}

describe("refresh tokens and soft logout", () => {
  it("refreshes on soft logout, retries once with the new token and persists it", async () => {
    const { server, store, client } = setup();
    server.on("GET", /\/whoami$/, (req) =>
      req.headers.Authorization === "Bearer new"
        ? { body: { user_id: "@me:test" } }
        : { status: 401, body: { errcode: "M_UNKNOWN_TOKEN", error: "expired", soft_logout: true } },
    );
    server.on("POST", /\/refresh$/, (req) => {
      expect(req.json).toEqual({ refresh_token: "r1" });
      expect(req.headers.Authorization).toBeUndefined();
      return { body: { access_token: "new", refresh_token: "r2", expires_in_ms: 60_000 } };
    });
    const who = await client.http.request<{ user_id: string }>("GET", "/_matrix/client/v3/account/whoami");
    expect(who.user_id).toBe("@me:test");
    expect(client.session).toMatchObject({ accessToken: "new", refreshToken: "r2" });
    expect(loadStoredSession(store)?.accessToken).toBe("new");
    expect(client.softLoggedOut).toBe(false);
  });

  it("shares one refresh between concurrent requests", async () => {
    const { server, client } = setup();
    server.on("GET", /\/x$/, (req) =>
      req.headers.Authorization === "Bearer new" ? { body: {} } : { status: 401, body: { errcode: "M_UNKNOWN_TOKEN", soft_logout: true } },
    );
    server.on("POST", /\/refresh$/, { body: { access_token: "new", refresh_token: "r2" } });
    await Promise.all([client.http.request("GET", "/x"), client.http.request("GET", "/x"), client.http.request("GET", "/x")]);
    expect(server.requestsTo(/\/refresh$/)).toHaveLength(1);
  });

  it("enters soft logout (keeping local data) when the refresh token is rejected, then re-authenticates on the same device", async () => {
    const { server, store, client } = setup();
    store.set(KEYS.sync, JSON.stringify({ version: 1, userId: "@me:test", since: "s1", rooms: [] }));
    server.on("GET", /\/x$/, (req) =>
      req.headers.Authorization === "Bearer fresh" ? { body: {} } : { status: 401, body: { errcode: "M_UNKNOWN_TOKEN", soft_logout: true } },
    );
    server.on("POST", /\/refresh$/, { status: 401, body: { errcode: "M_UNKNOWN_TOKEN", soft_logout: true } });
    await expect(client.http.request("GET", "/x")).rejects.toMatchObject({ errcode: "M_UNKNOWN_TOKEN" });
    expect(client.softLoggedOut).toBe(true);
    expect(client.loggedOutReason).toBeUndefined();
    expect(store.get(KEYS.sync)).not.toBeNull();

    server.on("POST", /\/login$/, (req) => {
      expect(req.json).toMatchObject({ identifier: { user: "@me:test" }, password: "pw", device_id: "DEV", refresh_token: true });
      return { body: { user_id: "@me:test", access_token: "fresh", device_id: "DEV", refresh_token: "r9" } };
    });
    // A long-poll that only ends when the client aborts it.
    server.on(
      "GET",
      /\/sync$/,
      (req) => new Promise((_, reject) => req.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
    );
    await client.reauthenticate("pw");
    expect(client.softLoggedOut).toBe(false);
    expect(client.session).toMatchObject({ accessToken: "fresh", deviceId: "DEV", refreshToken: "r9" });
    await client.http.request("GET", "/x");
    await client.stop();
  });

  it("wipes local state on a hard logout (soft_logout false)", async () => {
    const { server, store, client } = setup({ ...session, refreshToken: undefined });
    let reason = "";
    client.onLoggedOut = (r) => (reason = r);
    server.on("GET", /\/x$/, { status: 401, body: { errcode: "M_UNKNOWN_TOKEN", soft_logout: false } });
    await expect(client.http.request("GET", "/x")).rejects.toBeTruthy();
    await flushMicrotasks();
    expect(reason).toMatch(/session has ended/);
    expect(loadStoredSession(store)).toBeUndefined();
  });

  it("changes the password through UIA with the current password", async () => {
    const { server, client } = setup();
    server.on("POST", /\/account\/password$/, (req) => {
      const body = req.json as { auth?: Record<string, unknown>; new_password: string; logout_devices: boolean };
      if (!body.auth) return { status: 401, body: { flows: [{ stages: ["m.login.password"] }], session: "U" } };
      expect(body).toMatchObject({ new_password: "next-pass", logout_devices: true });
      expect(body.auth).toMatchObject({ type: "m.login.password", session: "U", password: "cur", identifier: { user: "@me:test" } });
      return { body: {} };
    });
    await client.changePassword("cur", "next-pass", true);
    expect(server.requestsTo(/\/account\/password$/)).toHaveLength(2);
  });
});

describe("attachments", () => {
  it("uploads first, then sends with the mxc URL", async () => {
    const { server, client } = setup();
    server.on("POST", /\/media\/v3\/upload$/, (req) => {
      expect(req.query.get("filename")).toBe("a.txt");
      expect(req.headers["Content-Type"]).toBe("text/plain");
      return { body: { content_uri: "mxc://hs.test/abc" } };
    });
    server.on("PUT", /\/send\//, { body: { event_id: "$f" } });
    const file = new File(["hello"], "a.txt", { type: "text/plain" });
    client.sendAttachment("!r:test", file);
    for (let i = 0; i < 30 && client.sendQueue.all()[0]?.status !== "sent"; i++) await flushMicrotasks();
    const put = server.requestsTo(/\/send\//)[0]!;
    expect(put.json).toMatchObject({ msgtype: "m.file", body: "a.txt", url: "mxc://hs.test/abc", info: { mimetype: "text/plain", size: 5 } });
  });

  it("marks an attachment interrupted by a reload as failed instead of resending without a file", () => {
    const store = new MemoryStore();
    saveSession(store, session);
    store.set(
      KEYS.pending,
      JSON.stringify([
        { txnId: "t", roomId: "!r:test", type: "m.room.message", content: { msgtype: "m.image", body: "p.png" }, status: "sending", createdTs: 1, attempts: 1, attachment: { name: "p.png", mimetype: "image/png", size: 3 } },
      ]),
    );
    const client = new MatrixClient({ session, store, transport: new FakeServer().transport, clock: new ManualClock() });
    client.sendQueue.restore(JSON.parse(store.get(KEYS.pending)!));
    expect(client.sendQueue.all()[0]).toMatchObject({ status: "failed", error: expect.stringMatching(/interrupted/) });
  });
});
