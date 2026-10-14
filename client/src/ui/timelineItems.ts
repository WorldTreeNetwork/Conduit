// Timeline rows from the room model: day plates, folded room setup, state
// lines, sender-grouped messages and local echoes. Pure, so it is unit tested.
import { relatesTo, type Aggregations, type MatrixEvent, type PendingEvent, type Room } from "../core";
import { continuesGroup, dayKey, describeStateEvent, eventKind } from "./format";

/** Is this pending send a change to another event (reaction or edit)? */
export function isRelationSend(p: Pick<PendingEvent, "type" | "content">): boolean {
  const rel = relatesTo(p).relType;
  return p.type === "m.reaction" || rel === "m.replace" || rel === "m.annotation";
}

export function isThreadSend(p: Pick<PendingEvent, "content">): boolean {
  return relatesTo(p).relType === "m.thread";
}

/**
 * In-flight reactions and edits as provisional events, so the timeline shows
 * them applied before the server confirms (failed ones are excluded).
 */
export function pendingRelationEvents(pending: PendingEvent[], selfId: string): MatrixEvent[] {
  return pending
    .filter((p) => isRelationSend(p) && p.status !== "failed")
    .map((p) => ({
      event_id: p.eventId ?? `~${p.txnId}`,
      type: p.type,
      sender: selfId,
      origin_server_ts: p.createdTs,
      content: p.content,
    }));
}

export type Item =
  | { kind: "day"; key: string; ts: number }
  | { kind: "state"; key: string; event: MatrixEvent; text: string }
  | { kind: "message"; key: string; event: MatrixEvent; grouped: boolean }
  | { kind: "pending"; key: string; pending: PendingEvent; grouped: boolean }
  | { kind: "creation"; key: string; sender: string; lines: { event: MatrixEvent; text: string }[] };

/** Setup events folded into the "created and configured" summary. */
const SETUP_TYPES = new Set([
  "m.room.create",
  "m.room.power_levels",
  "m.room.join_rules",
  "m.room.history_visibility",
  "m.room.guest_access",
  "m.room.name",
  "m.room.topic",
  "m.room.canonical_alias",
  "m.room.encryption",
  "m.room.avatar",
  "m.room.server_acl",
]);

/**
 * Collapse the creator's room-setup burst (create, own join, power levels,
 * rules, name, topic...) into one expandable line.
 */
export function foldCreation(items: Item[]): Item[] {
  const start = items.findIndex((i) => i.kind === "state" && i.event.type === "m.room.create");
  if (start < 0) return items;
  const first = items[start] as Extract<Item, { kind: "state" }>;
  const creator = first.event.sender;
  let end = start;
  let joined = false;
  while (end < items.length) {
    const item = items[end]!;
    if (item.kind !== "state" || item.event.sender !== creator) break;
    // Only the creator's initial join belongs to setup; later profile
    // changes stay visible.
    const initialJoin =
      !joined && item.event.type === "m.room.member" && item.event.state_key === creator && item.event.content.membership === "join";
    if (!SETUP_TYPES.has(item.event.type) && !initialJoin) break;
    if (initialJoin) joined = true;
    end++;
  }
  if (end - start < 3) return items;
  const lines = (items.slice(start, end) as Extract<Item, { kind: "state" }>[]).map(({ event, text }) => ({ event, text }));
  return [...items.slice(0, start), { kind: "creation", key: `creation-${first.key}`, sender: creator, lines }, ...items.slice(end)];
}

export function buildItems(room: Room, pending: PendingEvent[], selfId: string, aggregations?: Aggregations): Item[] {
  const hidden = aggregations?.hidden;
  let items: Item[] = [];
  const name = (id: string) => room.memberName(id);
  const memberContent = new Map<string, Record<string, unknown>>();
  let lastDay: string | undefined;
  let prevShown: MatrixEvent | undefined;
  for (const event of room.timeline) {
    const kind = eventKind(event);
    let text: string | undefined;
    if (event.type === "m.room.member" && event.state_key !== undefined) {
      text = describeStateEvent(event, name, memberContent.get(event.state_key));
      memberContent.set(event.state_key, event.content);
    } else if (kind === "state") {
      text = describeStateEvent(event, name);
    }
    if (kind === "hidden" || (kind === "state" && !text)) continue;
    if (hidden?.has(event.event_id)) continue;
    const day = dayKey(event.origin_server_ts);
    if (day !== lastDay) {
      items.push({ kind: "day", key: `day-${day}`, ts: event.origin_server_ts });
      lastDay = day;
      prevShown = undefined;
    }
    if (kind === "state") {
      items.push({ kind: "state", key: event.event_id, event, text: text! });
    } else {
      items.push({ kind: "message", key: event.event_id, event, grouped: continuesGroup(prevShown, event) });
    }
    prevShown = event;
  }
  items = foldCreation(items);
  let lastPending: PendingEvent | undefined;
  for (const p of pending) {
    if (p.eventId && room.hasEvent(p.eventId)) continue;
    if (isThreadSend(p)) continue;
    // Reactions and edits appear applied to their target; only failures
    // need their own row (with retry / delete).
    if (isRelationSend(p) && p.status !== "failed") continue;
    const day = dayKey(p.createdTs);
    if (day !== lastDay) {
      items.push({ kind: "day", key: `day-${day}`, ts: p.createdTs });
      lastDay = day;
      prevShown = undefined;
    }
    const grouped =
      (lastPending !== undefined && p.createdTs - lastPending.createdTs < 5 * 60_000) ||
      (lastPending === undefined && prevShown?.sender === selfId && eventKind(prevShown) === "message" &&
        p.createdTs - prevShown.origin_server_ts < 5 * 60_000);
    items.push({ kind: "pending", key: `txn-${p.txnId}`, pending: p, grouped });
    lastPending = p;
  }
  return items;
}

