import { describe, expect, it } from "vitest";
import { aggregate, displayContent, redactEvent, relatesTo, stripReplyFallback } from "./relations";
import { Room } from "./room";
import { makeEvent } from "./testing";
import { formatBytes, msgtypeFor, parseMxc } from "./media";

const ME = "@me:test";
const BOB = "@bob:test";

function msg(body: string, sender = ME, extra: Record<string, unknown> = {}) {
  return makeEvent({ type: "m.room.message", sender, content: { msgtype: "m.text", body, ...extra } });
}

describe("relations", () => {
  it("parses m.relates_to including replies and thread fallbacks", () => {
    const e = msg("x", ME, {
      "m.relates_to": { rel_type: "m.thread", event_id: "$root", is_falling_back: true, "m.in_reply_to": { event_id: "$prev" } },
    });
    expect(relatesTo(e)).toEqual({ relType: "m.thread", eventId: "$root", key: undefined, inReplyTo: "$prev", isFallingBack: true });
    expect(relatesTo(msg("plain"))).toEqual({});
  });

  it("applies only edits from the original sender, latest wins", () => {
    const original = msg("v0");
    const edit1 = msg("* v1", ME, { "m.new_content": { msgtype: "m.text", body: "v1" }, "m.relates_to": { rel_type: "m.replace", event_id: original.event_id } });
    const forged = msg("* evil", BOB, { "m.new_content": { msgtype: "m.text", body: "evil" }, "m.relates_to": { rel_type: "m.replace", event_id: original.event_id } });
    const edit2 = msg("* v2", ME, { "m.new_content": { msgtype: "m.text", body: "v2" }, "m.relates_to": { rel_type: "m.replace", event_id: original.event_id } });
    const agg = aggregate([original, edit1, forged, edit2], ME);
    expect(agg.hidden.has(edit1.event_id) && agg.hidden.has(forged.event_id)).toBe(true);
    expect(displayContent(original, agg)).toEqual({ content: { msgtype: "m.text", body: "v2" }, edited: true });
  });

  it("uses a bundled m.replace when the edit is not loaded", () => {
    const edit = msg("* b", ME, { "m.new_content": { msgtype: "m.text", body: "bundled" } });
    const original = { ...msg("a"), unsigned: { "m.relations": { "m.replace": edit } } };
    expect(displayContent(original, aggregate([original], ME)).content.body).toBe("bundled");
  });

  it("groups reactions by key, ignores duplicates and redacted ones, remembers our own", () => {
    const target = msg("hi", BOB);
    const react = (sender: string, key: string) =>
      makeEvent({ type: "m.reaction", sender, content: { "m.relates_to": { rel_type: "m.annotation", event_id: target.event_id, key } } });
    const mine = react(ME, "👍");
    const dup = react(ME, "👍");
    const bob = react(BOB, "👍");
    const heart = react(BOB, "❤️");
    const gone = { ...react(BOB, "🎉"), unsigned: { redacted_because: {} } };
    const groups = aggregate([target, mine, dup, bob, heart, gone], ME).reactions.get(target.event_id)!;
    expect(groups.map((g) => [g.key, g.count])).toEqual([
      ["👍", 2],
      ["❤️", 1],
    ]);
    expect(groups[0]!.ownEventId).toBe(mine.event_id);
  });

  it("collects thread replies, hides them from the main timeline and merges bundled counts", () => {
    const root = { ...msg("root", BOB), unsigned: { "m.relations": { "m.thread": { count: 5, current_user_participated: false } } } };
    const reply = msg("in thread", ME, { "m.relates_to": { rel_type: "m.thread", event_id: root.event_id } });
    const agg = aggregate([root, reply], ME);
    expect(agg.hidden.has(reply.event_id)).toBe(true);
    expect(agg.threads.get(root.event_id)).toMatchObject({ count: 5, participated: true });
    expect(agg.threadEvents.get(root.event_id)).toEqual([reply]);
  });

  it("strips legacy reply fallbacks", () => {
    expect(stripReplyFallback("> <@a:b> quoted\n> more\n\nreal answer")).toBe("real answer");
    expect(stripReplyFallback("no quote")).toBe("no quote");
  });

  it("redacts message content and keeps membership for member events", () => {
    const redaction = makeEvent({ type: "m.room.redaction", content: { redacts: "$x" } });
    expect(redactEvent(msg("secret"), redaction).content).toEqual({});
    const member = makeEvent({ type: "m.room.member", state_key: BOB, content: { membership: "join", displayname: "Bob" } });
    expect(redactEvent(member, redaction).content).toEqual({ membership: "join" });
  });

  it("applies live redactions to the loaded timeline and invalidates aggregations", () => {
    const room = new Room("!r:test");
    const target = msg("oops");
    room.addLiveEvents([target]);
    const before = room.aggregations(ME);
    room.addLiveEvents([makeEvent({ type: "m.room.redaction", sender: ME, content: { redacts: target.event_id } })]);
    expect(room.findEvent(target.event_id)?.unsigned?.redacted_because).toBeTruthy();
    expect(room.aggregations(ME)).not.toBe(before);
    expect(room.lastMessage()).toBeUndefined();
  });

  it("merges fetched thread history with live replies", () => {
    const room = new Room("!r:test");
    const root = msg("root");
    const old = { ...msg("old", BOB, { "m.relates_to": { rel_type: "m.thread", event_id: root.event_id } }), origin_server_ts: 1 };
    const live = msg("live", BOB, { "m.relates_to": { rel_type: "m.thread", event_id: root.event_id } });
    room.addLiveEvents([root, live]);
    room.addThreadHistory(root.event_id, [old, live]);
    expect(room.threadReplies(root.event_id, ME).map((e) => e.content.body)).toEqual(["old", "live"]);
  });
});

describe("media helpers", () => {
  it("parses mxc URIs strictly", () => {
    expect(parseMxc("mxc://example.org/AbC_1-2")).toEqual({ serverName: "example.org", mediaId: "AbC_1-2" });
    expect(parseMxc("https://example.org/x")).toBeUndefined();
    expect(parseMxc("mxc://example.org/../etc")).toBeUndefined();
  });
  it("maps MIME types to msgtypes and formats sizes", () => {
    expect(msgtypeFor("image/png")).toBe("m.image");
    expect(msgtypeFor("video/mp4")).toBe("m.video");
    expect(msgtypeFor("application/pdf")).toBe("m.file");
    expect(formatBytes(2048)).toBe("2.0 KB");
  });
});
