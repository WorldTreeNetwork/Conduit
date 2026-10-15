import { describe, expect, it } from "vitest";
import { Room, SNAPSHOT_TIMELINE_LIMIT } from "./room";
import { makeEvent } from "./testing";

const ME = "@me:test";

function member(userId: string, membership: string, displayname?: string) {
  return makeEvent({
    type: "m.room.member",
    state_key: userId,
    sender: userId,
    content: { membership, ...(displayname ? { displayname } : {}) },
  });
}

describe("room display name", () => {
  it("prefers m.room.name, then canonical alias", () => {
    const room = new Room("!r:test");
    room.applyState(makeEvent({ type: "m.room.canonical_alias", state_key: "", content: { alias: "#a:test" } }));
    expect(room.displayName(ME)).toBe("#a:test");
    room.applyState(makeEvent({ type: "m.room.name", state_key: "", content: { name: "Ops" } }));
    expect(room.displayName(ME)).toBe("Ops");
    room.applyState(makeEvent({ type: "m.room.name", state_key: "", content: { name: "" } }));
    expect(room.displayName(ME)).toBe("#a:test");
  });

  it("falls back to heroes, excluding self", () => {
    const room = new Room("!r:test");
    room.applyState(member(ME, "join"));
    expect(room.displayName(ME)).toBe("Empty room");
    room.applyState(member("@bob:test", "join", "Bob"));
    expect(room.displayName(ME)).toBe("Bob");
    room.applyState(member("@carol:test", "invite", "Carol"));
    expect(room.displayName(ME)).toBe("Bob and Carol");
    for (const n of ["d", "e", "f", "g"]) room.applyState(member(`@${n}:test`, "join"));
    expect(room.displayName(ME)).toBe("Bob, Carol, @d:test, @e:test, @f:test and 1 other");
  });

  it("names an empty room after people who left", () => {
    const room = new Room("!r:test");
    room.applyState(member(ME, "join"));
    room.applyState(member("@bob:test", "leave", "Bob"));
    expect(room.displayName(ME)).toBe("Empty room (was Bob)");
  });

  it("uses the server's m.heroes summary when present", () => {
    const room = new Room("!r:test");
    room.summary = { "m.heroes": ["@x:test", "@y:test"], "m.joined_member_count": 5, "m.invited_member_count": 0 };
    expect(room.displayName(ME)).toBe("@x:test, @y:test and 2 others");
  });

  it("names an invite from stripped state or the inviter", () => {
    const room = new Room("!r:test");
    room.membership = "invite";
    room.inviteState = [
      { type: "m.room.member", state_key: ME, sender: "@bob:test", content: { membership: "invite" } },
      { type: "m.room.member", state_key: "@bob:test", sender: "@bob:test", content: { membership: "join", displayname: "Bob" } },
    ];
    expect(room.displayName(ME)).toBe("Bob");
    expect(room.inviter(ME)).toBe("@bob:test");
    room.inviteState.push({ type: "m.room.name", state_key: "", sender: "@bob:test", content: { name: "Plans" } });
    expect(room.displayName(ME)).toBe("Plans");
  });

  it("disambiguates clashing member display names", () => {
    const room = new Room("!r:test");
    room.applyState(member("@a:test", "join", "Sam"));
    room.applyState(member("@b:test", "join", "Sam"));
    expect(room.memberName("@a:test")).toBe("Sam (@a:test)");
    room.applyState(member("@b:test", "join", "Samantha"));
    expect(room.memberName("@a:test")).toBe("Sam");
    expect(room.memberName("@nobody:test")).toBe("@nobody:test");
  });
});

describe("timeline folding", () => {
  it("folds live state events into current state and de-duplicates", () => {
    const room = new Room("!r:test");
    const topic = makeEvent({ type: "m.room.topic", state_key: "", content: { topic: "first" } });
    const message = makeEvent({ type: "m.room.message", content: { msgtype: "m.text", body: "hi" } });
    room.addLiveEvents([topic, message]);
    room.addLiveEvents([message]);
    expect(room.timeline).toHaveLength(2);
    expect(room.topic).toBe("first");
    expect(room.lastMessage()?.content.body).toBe("hi");
  });

  it("prepends history oldest-first without touching current state", () => {
    const room = new Room("!r:test");
    room.applyState(makeEvent({ type: "m.room.topic", state_key: "", content: { topic: "now" } }));
    const live = makeEvent({ type: "m.room.message", content: { body: "3" } });
    room.addLiveEvents([live]);
    const one = makeEvent({ type: "m.room.message", content: { body: "1" } });
    const oldTopic = makeEvent({ type: "m.room.topic", state_key: "", content: { topic: "then" } });
    // /messages dir=b returns newest first.
    const added = room.addHistoricalEvents([live, oldTopic, one]);
    expect(added).toBe(2);
    expect(room.timeline.map((e) => e.content.body ?? e.content.topic)).toEqual(["1", "then", "3"]);
    expect(room.topic).toBe("now");
  });

  it("restarts history on a limited sync", () => {
    const room = new Room("!r:test");
    room.addLiveEvents([makeEvent({ type: "m.room.message", content: { body: "old" } })]);
    room.historyExhausted = true;
    room.resetTimeline("t9");
    expect(room.timeline).toHaveLength(0);
    expect(room.prevBatch).toBe("t9");
    expect(room.historyExhausted).toBe(false);
  });

  it("round-trips through a snapshot and drops a stale token when trimming", () => {
    const room = new Room("!r:test");
    room.applyState(member(ME, "join"));
    room.prevBatch = "p1";
    room.unread = { notifications: 2, highlights: 1 };
    room.addLiveEvents([makeEvent({ type: "m.room.message", content: { body: "x" } })]);
    const restored = Room.fromSnapshot(JSON.parse(JSON.stringify(room.toSnapshot())));
    expect(restored.prevBatch).toBe("p1");
    expect(restored.unread).toEqual({ notifications: 2, highlights: 1 });
    expect(restored.member(ME)?.membership).toBe("join");
    expect(restored.hasEvent(room.timeline[0]!.event_id)).toBe(true);

    for (let i = 0; i < SNAPSHOT_TIMELINE_LIMIT + 5; i++) {
      room.addLiveEvents([makeEvent({ type: "m.room.message", content: { body: `m${i}` } })]);
    }
    const trimmed = room.toSnapshot();
    expect(trimmed.timeline).toHaveLength(SNAPSHOT_TIMELINE_LIMIT);
    expect(trimmed.prevBatch).toBeUndefined();
  });

  it("computes power levels with creator fallback", () => {
    const room = new Room("!r:test");
    room.applyState(makeEvent({ type: "m.room.create", state_key: "", sender: ME, content: {} }));
    expect(room.powerLevel(ME)).toBe(100);
    room.applyState(
      makeEvent({ type: "m.room.power_levels", state_key: "", content: { users: { [ME]: 50 }, users_default: 10 } }),
    );
    expect(room.powerLevel(ME)).toBe(50);
    expect(room.powerLevel("@x:test")).toBe(10);
  });
});
