import { describe, expect, it } from "vitest";
import { Room } from "../core/room";
import { makeEvent } from "../core/testing";
import type { PendingEvent } from "../core/sendQueue";
import { parseComposer } from "./Composer";
import { continuesGroup, describeStateEvent, formatDay, messageView } from "./format";
import { buildItems } from "./timelineItems";
import { parseHash, routeHref } from "./hooks";

const ME = "@me:test";
const name = (id: string) => id.slice(1, id.indexOf(":"));

describe("state event descriptions", () => {
  it("describes membership transitions", () => {
    const join = makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: "@bob:test", content: { membership: "join" } });
    expect(describeStateEvent(join, name)).toBe("bob joined");
    const invite = makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: "@amy:test", content: { membership: "invite" } });
    expect(describeStateEvent(invite, name)).toBe("amy invited bob");
    const decline = makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: "@bob:test", content: { membership: "leave" } });
    expect(describeStateEvent(decline, name, { membership: "invite" })).toBe("bob declined the invitation");
    expect(describeStateEvent(decline, name, { membership: "join" })).toBe("bob left");
    const kick = makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: "@amy:test", content: { membership: "leave", reason: "spam" } });
    expect(describeStateEvent(kick, name, { membership: "join" })).toBe("amy removed bob: spam");
    const rename = makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: "@bob:test", content: { membership: "join", displayname: "Bobby" } });
    expect(describeStateEvent(rename, name, { membership: "join", displayname: "Bob" })).toBe("Bob changed their display name to Bobby");
    expect(describeStateEvent(rename, name, { membership: "join" })).toBe("@bob:test set their display name to Bobby");
    const same = makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: "@bob:test", content: { membership: "join" } });
    expect(describeStateEvent(same, name, { membership: "join" })).toBeUndefined();
  });

  it("describes room settings and ignores unknown state", () => {
    expect(describeStateEvent(makeEvent({ type: "m.room.topic", state_key: "", sender: "@a:t", content: { topic: "x" } }), name)).toBe(
      "a changed the topic to “x”",
    );
    expect(describeStateEvent(makeEvent({ type: "m.room.join_rules", state_key: "", sender: "@a:t", content: { join_rule: "public" } }), name)).toBe(
      "a made the room public",
    );
    expect(describeStateEvent(makeEvent({ type: "org.example.custom", state_key: "", content: {} }), name)).toBeUndefined();
  });
});

describe("message views", () => {
  it("handles notices, emotes, redactions and encrypted events", () => {
    expect(messageView(makeEvent({ type: "m.room.message", content: { msgtype: "m.notice", body: "n" } }))).toEqual({ msgtype: "m.notice", body: "n" });
    expect(messageView(makeEvent({ type: "m.room.message", content: {} })).msgtype).toBe("m.redacted");
    expect(messageView(makeEvent({ type: "m.room.encrypted", content: {} })).msgtype).toBe("m.bad.encrypted");
  });

  it("groups same-sender messages within five minutes", () => {
    const a = makeEvent({ type: "m.room.message", sender: ME, origin_server_ts: 1_000_000, content: { body: "a" } });
    const b = makeEvent({ type: "m.room.message", sender: ME, origin_server_ts: 1_000_000 + 60_000, content: { body: "b" } });
    const c = makeEvent({ type: "m.room.message", sender: ME, origin_server_ts: 1_000_000 + 10 * 60_000, content: { body: "c" } });
    expect(continuesGroup(a, b)).toBe(true);
    expect(continuesGroup(b, c)).toBe(false);
    expect(continuesGroup(undefined, a)).toBe(false);
  });

  it("labels today and yesterday", () => {
    const now = new Date(2026, 9, 14, 12).getTime();
    expect(formatDay(now - 1000, now)).toBe("Today");
    expect(formatDay(now - 86_400_000, now)).toBe("Yesterday");
  });
});

describe("timeline items", () => {
  function setupRoom(): Room {
    const room = new Room("!r:test");
    const t = 1_700_000_000_000;
    room.addLiveEvents([
      makeEvent({ type: "m.room.create", state_key: "", sender: ME, origin_server_ts: t, content: {} }),
      makeEvent({ type: "m.room.member", state_key: ME, sender: ME, origin_server_ts: t + 1, content: { membership: "join" } }),
      makeEvent({ type: "m.room.power_levels", state_key: "", sender: ME, origin_server_ts: t + 2, content: {} }),
      makeEvent({ type: "m.room.name", state_key: "", sender: ME, origin_server_ts: t + 3, content: { name: "R" } }),
      makeEvent({ type: "m.room.member", state_key: "@bob:test", sender: ME, origin_server_ts: t + 4, content: { membership: "invite" } }),
      makeEvent({ type: "m.room.message", sender: ME, origin_server_ts: t + 5, content: { body: "hi" } }),
      makeEvent({ type: "m.room.message", sender: ME, origin_server_ts: t + 6, content: { body: "again" } }),
    ]);
    return room;
  }

  it("folds the creator's setup burst but keeps invites and messages", () => {
    const items = buildItems(setupRoom(), [], ME);
    expect(items.map((i) => i.kind)).toEqual(["day", "creation", "state", "message", "message"]);
    const creation = items[1] as Extract<(typeof items)[number], { kind: "creation" }>;
    expect(creation.lines.map((l) => l.event.type)).toEqual(["m.room.create", "m.room.member", "m.room.power_levels", "m.room.name"]);
    expect((items[4] as { grouped: boolean }).grouped).toBe(true);
  });

  it("appends local echoes after server events and hides reconciled ones", () => {
    const room = setupRoom();
    const pending: PendingEvent[] = [
      { txnId: "t1", roomId: room.roomId, type: "m.room.message", content: { body: "sending" }, status: "sending", createdTs: 1_700_000_000_010, attempts: 1 },
      { txnId: "t2", roomId: room.roomId, type: "m.room.message", content: { body: "done" }, status: "sent", eventId: room.timeline[5]!.event_id, createdTs: 1_700_000_000_011, attempts: 1 },
    ];
    const items = buildItems(room, pending, ME);
    const echoes = items.filter((i) => i.kind === "pending");
    expect(echoes).toHaveLength(1);
    expect(echoes[0]).toMatchObject({ key: "txn-t1", grouped: true });
  });

  it("does not fold a short history that lacks the create event", () => {
    const room = new Room("!r:test");
    room.addLiveEvents([makeEvent({ type: "m.room.name", state_key: "", sender: ME, content: { name: "x" } })]);
    expect(buildItems(room, [], ME).map((i) => i.kind)).toEqual(["day", "state"]);
  });
});

describe("composer parsing", () => {
  it("parses emotes, escapes and blank input", () => {
    expect(parseComposer("  ")).toBeUndefined();
    expect(parseComposer("/me waves\n")).toEqual({ body: "waves", msgtype: "m.emote" });
    expect(parseComposer("//me is literal")).toEqual({ body: "/me is literal", msgtype: "m.text" });
    expect(parseComposer("line 1\nline 2")).toEqual({ body: "line 1\nline 2", msgtype: "m.text" });
  });
});

describe("routes", () => {
  it("round-trips room routes with encoded IDs", () => {
    const route = { name: "room" as const, roomId: "!abc:server.test" };
    expect(parseHash(routeHref(route))).toEqual(route);
    expect(parseHash("#/settings")).toEqual({ name: "settings" });
    expect(parseHash("#/nonsense")).toEqual({ name: "home" });
    expect(parseHash("#/room/%E0%A4%A")).toEqual({ name: "home" });
  });
});
