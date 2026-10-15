import { describe, expect, it } from "vitest";
import { MatrixClient, clearStoredSession, loadStoredSession, saveSession } from "./client";
import { ManualClock, flushMicrotasks } from "./clock";
import { MemoryStore, KEYS } from "./store";
import { FakeServer, makeEvent } from "./testing";
import type { Session, SyncResponse } from "./types";

const session: Session = { homeserverUrl: "https://hs.test", userId: "@me:test", accessToken: "T", deviceId: "D" };
const ROOM = "!room:test";

function joinedSync(next: string, events: ReturnType<typeof makeEvent>[], extra: Partial<SyncResponse> = {}): SyncResponse {
  return {
    next_batch: next,
    rooms: {
      join: {
        [ROOM]: {
          timeline: { events, limited: false, prev_batch: `p-${next}` },
          state: { events: [] },
          unread_notifications: { notification_count: 2, highlight_count: 0 },
        },
      },
    },
    ...extra,
  };
}

/**
 * A scripted /sync: each call takes the next queued response; with nothing
 * queued it parks until `push` (like a long-poll) unless the signal aborts.
 */
function scriptedSync(server: FakeServer) {
  const queue: (SyncResponse | { networkError: true } | { status: number; body: unknown })[] = [];
  let wake: (() => void) | undefined;
  server.on("GET", /\/sync$/, async (req) => {
    while (queue.length === 0) {
      await new Promise<void>((resolve, reject) => {
        wake = resolve;
        req.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
    }
    const next = queue.shift()!;
    if ("networkError" in next) return { networkError: true };
    if ("status" in next) return next;
    return { body: next };
  });
  return {
    push(response: (typeof queue)[number]) {
      queue.push(response);
      wake?.();
    },
  };
}

function makeClient(store = new MemoryStore()) {
  const server = new FakeServer();
  const clock = new ManualClock();
  const sync = scriptedSync(server);
  const client = new MatrixClient({ session, store, transport: server.transport, clock });
  return { server, clock, sync, client, store };
}

async function settle(_client: MatrixClient, predicate: () => boolean) {
  for (let i = 0; i < 50 && !predicate(); i++) await flushMicrotasks();
  expect(predicate()).toBe(true);
}

describe("sync processing", () => {
  it("does an initial sync, then long-polls with the since token and the filter", async () => {
    const { server, sync, client } = makeClient();
    client.start();
    sync.push(joinedSync("s1", [makeEvent({ type: "m.room.message", content: { body: "hello" } })]));
    await settle(client, () => client.syncHealth.state === "live");
    sync.push(joinedSync("s2", []));
    await settle(client, () => server.requestsTo(/\/sync$/).length >= 3);
    const [first, second] = server.requestsTo(/\/sync$/);
    expect(first!.query.get("since")).toBeNull();
    expect(first!.query.get("timeout")).toBe("0");
    expect(first!.query.get("use_state_after")).toBe("true");
    expect(second!.query.get("since")).toBe("s1");
    expect(second!.query.get("timeout")).toBe("30000");
    expect(JSON.parse(first!.query.get("filter")!).room.timeline.limit).toBe(30);
    const room = client.getRoom(ROOM)!;
    expect(room.unread.notifications).toBe(2);
    expect(client.roomList()[0]!.preview?.body).toBe("hello");
    await client.stop();
  });

  it("uses state_after exclusively and keeps timeline state as history", async () => {
    const { client } = makeClient();
    const old = makeEvent({ type: "m.room.name", state_key: "", content: { name: "Timeline name" } });
    const current = makeEvent({ type: "m.room.name", state_key: "", content: { name: "Current name" } });
    const response = joinedSync("s1", [old]);
    response.rooms!.join![ROOM]!.state_after = { events: [current] };
    await client.processSync(response, true);
    expect(client.getRoom(ROOM)!.explicitName).toBe("Current name");
    expect(client.getRoom(ROOM)!.timeline[0]!.content.name).toBe("Timeline name");

    const delta = joinedSync("s2", [makeEvent({ type: "m.room.name", state_key: "", content: { name: "Ignored timeline change" } })]);
    delta.rooms!.join![ROOM]!.state_after = { events: [] };
    delta.rooms!.join![ROOM]!.timeline!.limited = true;
    await client.processSync(delta, false);
    expect(client.getRoom(ROOM)!.explicitName).toBe("Current name");
    expect(client.getRoom(ROOM)!.timeline[0]!.content.name).toBe("Ignored timeline change");
  });

  it("updates redacted room state only from state_after while still redacting timeline content", async () => {
    const { client } = makeClient();
    const name = makeEvent({ type: "m.room.name", state_key: "", content: { name: "Authoritative" } });
    const response = joinedSync("s1", [name]);
    response.rooms!.join![ROOM]!.state_after = { events: [name] };
    await client.processSync(response, true);
    const redaction = makeEvent({ type: "m.room.redaction", content: { redacts: name.event_id } });
    const delta = joinedSync("s2", [redaction]);
    delta.rooms!.join![ROOM]!.state_after = { events: [] };
    await client.processSync(delta, false);
    expect(client.getRoom(ROOM)!.explicitName).toBe("Authoritative");
    expect(client.getRoom(ROOM)!.timeline[0]!.content).toEqual({});
    const update = joinedSync("s3", []);
    update.rooms!.join![ROOM]!.state_after = { events: [{ ...name, content: {} }] };
    await client.processSync(update, false);
    expect(client.getRoom(ROOM)!.explicitName).toBeUndefined();
  });

  it("refreshes a cached timeline state event when state_after carries its redaction", async () => {
    const { client } = makeClient();
    const name = makeEvent({ type: "m.room.name", state_key: "", content: { name: "Removed name" } });
    const response = joinedSync("s1", [name]);
    response.rooms!.join![ROOM]!.state_after = { events: [name] };
    await client.processSync(response, true);
    const delta = joinedSync("s2", []);
    delta.rooms!.join![ROOM]!.state_after = {
      events: [{ ...name, content: {}, unsigned: { redacted_because: { ...makeEvent({ type: "m.room.redaction", content: { redacts: name.event_id } }) } } }],
    };
    await client.processSync(delta, false);
    expect(client.getRoom(ROOM)!.explicitName).toBeUndefined();
    expect(client.getRoom(ROOM)!.timeline[0]!.content).toEqual({});
  });

  it("preserves authoritative state_after across persistence and reconnects", async () => {
    const { client, sync, store } = makeClient();
    client.start();
    const response = joinedSync("s8", [makeEvent({ type: "m.room.name", state_key: "", content: { name: "Old name" } })]);
    response.rooms!.join![ROOM]!.state_after = {
      events: [makeEvent({ type: "m.room.name", state_key: "", content: { name: "Saved current name" } })],
    };
    sync.push(response);
    await settle(client, () => client.getRoom(ROOM)?.explicitName === "Saved current name");
    await client.stop();
    const restored = makeClient(store);
    restored.client.start();
    expect(restored.client.getRoom(ROOM)!.explicitName).toBe("Saved current name");
    await settle(restored.client, () => restored.server.requestsTo(/\/sync$/).length === 1);
    expect(restored.server.requestsTo(/\/sync$/)[0]!.query.get("since")).toBe("s8");
    await restored.client.stop();
  });

  it("persists the since token with room state and resumes from it", async () => {
    const store = new MemoryStore();
    const a = makeClient(store);
    a.client.start();
    a.sync.push(joinedSync("s7", [makeEvent({ type: "m.room.name", state_key: "", content: { name: "Saved" } })]));
    await settle(a.client, () => a.client.syncHealth.state === "live");
    await a.client.stop();

    const b = makeClient(store);
    b.client.start();
    expect(b.client.syncHealth.ready).toBe(true);
    expect(b.client.roomList()[0]!.name).toBe("Saved");
    await settle(b.client, () => b.server.requestsTo(/\/sync$/).length === 1);
    expect(b.server.requestsTo(/\/sync$/)[0]!.query.get("since")).toBe("s7");
    await b.client.stop();
  });

  it("moves to reconnecting with backoff on failure and recovers", async () => {
    const { server, sync, client, clock } = makeClient();
    client.start();
    sync.push({ networkError: true });
    await settle(client, () => client.syncHealth.state === "reconnecting");
    expect(client.syncHealth.failures).toBe(1);
    expect(client.syncHealth.nextRetryAt).toBe(clock.now() + 1000);
    sync.push({ networkError: true });
    await clock.advance(1000);
    await settle(client, () => client.syncHealth.failures === 2);
    expect(client.syncHealth.nextRetryAt).toBe(clock.now() + 2000);
    // "Retry now" skips the remaining backoff.
    sync.push(joinedSync("s1", []));
    client.sync.retryNow();
    await settle(client, () => client.syncHealth.state === "live");
    expect(server.requestsTo(/\/sync$/).length).toBeGreaterThanOrEqual(3);
    await client.stop();
  });

  it("stops and clears the session on M_UNKNOWN_TOKEN", async () => {
    const { sync, client, store } = makeClient();
    saveSession(store, session);
    let reason = "";
    client.onLoggedOut = (r) => (reason = r);
    client.start();
    sync.push({ status: 401, body: { errcode: "M_UNKNOWN_TOKEN", error: "gone" } });
    await settle(client, () => client.syncHealth.state === "error");
    expect(reason).toMatch(/session has ended/);
    expect(loadStoredSession(store)).toBeUndefined();
  });

  it("tracks invites and removes rooms we left", async () => {
    const { sync, client } = makeClient();
    client.start();
    sync.push({
      next_batch: "s1",
      rooms: {
        invite: {
          "!inv:test": {
            invite_state: {
              events: [{ type: "m.room.member", state_key: "@me:test", sender: "@bob:test", content: { membership: "invite" } }],
            },
          },
        },
      },
    });
    await settle(client, () => client.roomList().length === 1);
    expect(client.roomList()[0]).toMatchObject({ membership: "invite", inviter: "@bob:test", name: "@bob:test" });
    sync.push({ next_batch: "s2", rooms: { leave: { "!inv:test": {} } } });
    await settle(client, () => client.roomList().length === 0);
    await client.stop();
  });

  it("resets the timeline on a limited sync", async () => {
    const { sync, client } = makeClient();
    client.start();
    sync.push(joinedSync("s1", [makeEvent({ type: "m.room.message", content: { body: "a" } })]));
    await settle(client, () => client.getRoom(ROOM)?.timeline.length === 1);
    const gap = joinedSync("s2", [makeEvent({ type: "m.room.message", content: { body: "z" } })]);
    gap.rooms!.join![ROOM]!.timeline!.limited = true;
    gap.rooms!.join![ROOM]!.timeline!.prev_batch = "gap";
    sync.push(gap);
    await settle(client, () => client.getRoom(ROOM)?.prevBatch === "gap");
    expect(client.getRoom(ROOM)!.timeline.map((e) => e.content.body)).toEqual(["z"]);
    await client.stop();
  });
});

describe("sending with local echo", () => {
  it("echoes immediately, PUTs with a txn id, and drops the echo when the remote event arrives", async () => {
    const { server, sync, client } = makeClient();
    server.on("PUT", /\/send\/m.room.message\//, { body: { event_id: "$sent" } });
    client.start();
    sync.push(joinedSync("s1", []));
    await settle(client, () => client.syncHealth.state === "live");
    const pending = client.sendMessage(ROOM, "hi");
    expect(client.sendQueue.forRoom(ROOM)).toHaveLength(1);
    await settle(client, () => client.sendQueue.forRoom(ROOM)[0]?.status === "sent");
    const put = server.requestsTo(/\/send\//)[0]!;
    expect(put.path).toBe(`/_matrix/client/v3/rooms/${encodeURIComponent(ROOM)}/send/m.room.message/${encodeURIComponent(pending.txnId)}`);
    expect(put.json).toEqual({ msgtype: "m.text", body: "hi" });
    expect(client.isIdle).toBe(true);
    sync.push(joinedSync("s2", [makeEvent({ event_id: "$sent", sender: "@me:test", type: "m.room.message", content: { body: "hi" } })]));
    await settle(client, () => client.sendQueue.forRoom(ROOM).length === 0);
    await client.stop();
  });

  it("drops the echo at once if the remote echo beat the PUT response", async () => {
    const { server, sync, client } = makeClient();
    let release!: () => void;
    server.on("PUT", /\/send\//, async () => {
      await new Promise<void>((r) => (release = r));
      return { body: { event_id: "$early" } };
    });
    client.start();
    sync.push(joinedSync("s1", []));
    await settle(client, () => client.syncHealth.state === "live");
    client.sendMessage(ROOM, "race");
    await settle(client, () => !!release);
    sync.push(joinedSync("s2", [makeEvent({ event_id: "$early", sender: "@me:test", type: "m.room.message", content: { body: "race" } })]));
    await settle(client, () => client.getRoom(ROOM)!.hasEvent("$early"));
    release();
    await settle(client, () => client.sendQueue.forRoom(ROOM).length === 0);
    await client.stop();
  });

  it("marks a send failed after retries, keeps the txn id on retry, and can discard", async () => {
    const { server, client, clock, sync } = makeClient();
    server.once("PUT", /\/send\//, { networkError: true });
    server.once("PUT", /\/send\//, { networkError: true });
    server.once("PUT", /\/send\//, { networkError: true });
    client.start();
    sync.push(joinedSync("s1", []));
    const item = client.sendMessage(ROOM, "flaky");
    await flushMicrotasks();
    await clock.advance(500);
    await clock.advance(1000);
    await settle(client, () => client.sendQueue.forRoom(ROOM)[0]?.status === "failed");
    expect(client.sendQueue.forRoom(ROOM)[0]!.error).toMatch(/reach the server/);
    expect(server.requestsTo(/\/send\//)).toHaveLength(3);

    server.on("PUT", /\/send\//, { body: { event_id: "$ok" } });
    client.retrySend(item.txnId);
    await settle(client, () => client.sendQueue.forRoom(ROOM)[0]?.status === "sent");
    const txnIds = new Set(server.requestsTo(/\/send\//).map((r) => r.path.split("/").pop()));
    expect(txnIds.size).toBe(1);

    server.once("PUT", /\/send\//, { status: 403, body: { errcode: "M_FORBIDDEN", error: "muted" } });
    const doomed = client.sendMessage(ROOM, "never");
    await settle(client, () => client.sendQueue.all().some((p) => p.txnId === doomed.txnId && p.status === "failed"));
    client.discardSend(doomed.txnId);
    expect(client.sendQueue.all().some((p) => p.txnId === doomed.txnId)).toBe(false);
    await client.stop();
  });

  it("persists failed sends and restores them across restarts", async () => {
    const store = new MemoryStore();
    const a = makeClient(store);
    a.server.on("PUT", /\/send\//, { status: 400, body: { errcode: "M_UNKNOWN", error: "bad" } });
    a.client.start();
    a.client.sendMessage(ROOM, "keep me");
    await settle(a.client, () => a.client.sendQueue.all()[0]?.status === "failed");
    await a.client.stop();
    expect(store.get(KEYS.pending)).toContain("keep me");
    const b = makeClient(store);
    b.client.start();
    expect(b.client.sendQueue.all()[0]).toMatchObject({ status: "failed", content: { body: "keep me" } });
    await b.client.stop();
  });
});

describe("pagination", () => {
  it("pages back from prev_batch and stops when end is absent", async () => {
    const { server, sync, client } = makeClient();
    const older = [
      makeEvent({ type: "m.room.message", content: { body: "two" } }),
      makeEvent({ type: "m.room.message", content: { body: "one" } }),
    ];
    server.once("GET", /\/messages$/, { body: { chunk: older, start: "p-s1", end: "e1" } });
    server.once("GET", /\/messages$/, { body: { chunk: [], start: "e1" } });
    client.start();
    sync.push(joinedSync("s1", [makeEvent({ type: "m.room.message", content: { body: "three" } })]));
    await settle(client, () => client.syncHealth.state === "live");
    expect(await client.paginateBack(ROOM)).toBe(2);
    const first = server.requestsTo(/\/messages$/)[0]!;
    expect(first.query.get("dir")).toBe("b");
    expect(first.query.get("from")).toBe("p-s1");
    expect(client.getRoom(ROOM)!.timeline.map((e) => e.content.body)).toEqual(["one", "two", "three"]);
    expect(await client.paginateBack(ROOM)).toBe(0);
    expect(server.requestsTo(/\/messages$/)[1]!.query.get("from")).toBe("e1");
    expect(client.getRoom(ROOM)!.historyExhausted).toBe(true);
    expect(await client.paginateBack(ROOM)).toBe(0);
    expect(server.requestsTo(/\/messages$/)).toHaveLength(2);
    await client.stop();
  });
});

describe("session storage", () => {
  it("round-trips and clears", () => {
    const store = new MemoryStore();
    saveSession(store, session);
    expect(loadStoredSession(store)).toEqual(session);
    clearStoredSession(store);
    expect(loadStoredSession(store)).toBeUndefined();
  });
});
