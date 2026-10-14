// Turning events into words. Kept free of React so it is unit-testable.
import type { MatrixEvent, Room } from "../core";

export type TimelineKind = "message" | "state" | "hidden";

export function eventKind(event: MatrixEvent): TimelineKind {
  if (event.type === "m.room.message") return "message";
  if (event.type === "m.room.encrypted") return "message";
  if (event.state_key !== undefined) {
    return describeStateEvent(event, (id) => id) ? "state" : "hidden";
  }
  return "hidden";
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * One compact line for a state event, or undefined when the event is not
 * worth showing (e.g. power-level churn during room creation is still shown
 * but unknown custom state is not).
 */
export function describeStateEvent(
  event: MatrixEvent,
  name: (userId: string) => string,
  /** Fallback when the server omits unsigned.prev_content. */
  knownPrev?: Record<string, unknown>,
): string | undefined {
  const who = name(event.sender);
  const c = event.content;
  const prev = event.unsigned?.prev_content ?? knownPrev ?? {};
  switch (event.type) {
    case "m.room.create":
      return `${who} created the room`;
    case "m.room.member": {
      const target = event.state_key ?? "";
      const targetName = str(c.displayname) ?? name(target);
      const membership = str(c.membership);
      const prevMembership = str(prev.membership);
      const reason = str(c.reason);
      const suffix = reason ? `: ${reason}` : "";
      switch (membership) {
        case "join":
          if (prevMembership === "join") {
            const before = str(prev.displayname);
            const after = str(c.displayname);
            if (before !== after) {
              if (!after) return `${before ?? target} removed their display name`;
              if (!before) return `${target} set their display name to ${after}`;
              return `${before} changed their display name to ${after}`;
            }
            if (prev.avatar_url !== c.avatar_url) return `${targetName} changed their avatar`;
            return undefined;
          }
          return `${targetName} joined`;
        case "invite":
          return `${who} invited ${targetName}${suffix}`;
        case "leave":
          if (target !== event.sender) {
            if (prevMembership === "invite") return `${who} withdrew ${name(target)}'s invitation${suffix}`;
            if (prevMembership === "ban") return `${who} unbanned ${name(target)}${suffix}`;
            return `${who} removed ${name(target)}${suffix}`;
          }
          if (prevMembership === "invite") return `${name(target)} declined the invitation`;
          return `${name(target)} left${suffix}`;
        case "ban":
          return `${who} banned ${name(target)}${suffix}`;
        case "knock":
          return `${name(target)} asked to join${suffix}`;
        default:
          return undefined;
      }
    }
    case "m.room.name": {
      const value = str(c.name);
      return value ? `${who} named the room ${value}` : `${who} removed the room name`;
    }
    case "m.room.topic": {
      const value = str(c.topic);
      return value ? `${who} changed the topic to “${value}”` : `${who} removed the topic`;
    }
    case "m.room.canonical_alias": {
      const value = str(c.alias);
      return value ? `${who} set the room address to ${value}` : `${who} removed the room address`;
    }
    case "m.room.join_rules": {
      const rule = str(c.join_rule);
      if (rule === "public") return `${who} made the room public`;
      if (rule === "invite") return `${who} made the room invite-only`;
      if (rule === "knock") return `${who} let people ask to join`;
      return rule ? `${who} set who can join to ${rule}` : undefined;
    }
    case "m.room.history_visibility": {
      const value = str(c.history_visibility);
      const labels: Record<string, string> = {
        shared: "members (since they could see the room)",
        invited: "members since they were invited",
        joined: "members since they joined",
        world_readable: "anyone",
      };
      return value ? `${who} made future history visible to ${labels[value] ?? value}` : undefined;
    }
    case "m.room.guest_access":
      return c.guest_access === "can_join" ? `${who} let guests join` : `${who} stopped guests joining`;
    case "m.room.encryption":
      return `${who} turned on end-to-end encryption`;
    case "m.room.power_levels":
      return `${who} changed permissions`;
    case "m.room.avatar":
      return str(c.url) ? `${who} changed the room avatar` : `${who} removed the room avatar`;
    case "m.room.server_acl":
      return `${who} changed the server access list`;
    case "m.room.tombstone":
      return `${who} upgraded this room`;
    default:
      return undefined;
  }
}

export interface MessageView {
  msgtype: string;
  body: string;
}

export function messageView(event: MatrixEvent): MessageView {
  if (event.type === "m.room.encrypted") {
    return { msgtype: "m.bad.encrypted", body: "Encrypted message. This client cannot decrypt it yet." };
  }
  const body = str(event.content.body);
  const msgtype = str(event.content.msgtype) ?? "m.text";
  if (event.unsigned?.redacted_because || body === undefined) {
    return { msgtype: "m.redacted", body: "Message deleted" };
  }
  return { msgtype, body };
}

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayFormat = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric" });
const dayYearFormat = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" });

export function formatTime(ts: number): string {
  return timeFormat.format(new Date(ts));
}

export function dayKey(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

export function formatDay(ts: number, now = Date.now()): string {
  if (dayKey(ts) === dayKey(now)) return "Today";
  if (dayKey(ts) === dayKey(now - 86_400_000)) return "Yesterday";
  const date = new Date(ts);
  return date.getFullYear() === new Date(now).getFullYear() ? dayFormat.format(date) : dayYearFormat.format(date);
}

/** Short relative stamp for room previews. */
export function formatPreviewTime(ts: number, now = Date.now()): string {
  if (!ts) return "";
  if (dayKey(ts) === dayKey(now)) return formatTime(ts);
  if (now - ts < 6 * 86_400_000) return new Intl.DateTimeFormat(undefined, { weekday: "short" }).format(new Date(ts));
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(ts));
}

/** Initial for a plate avatar: first letter after any sigil. */
export function initialOf(name: string): string {
  const clean = name.replace(/^[@#!+]/, "");
  const first = [...clean][0];
  return (first ?? "?").toUpperCase();
}

/** Stable hue bucket for a user, so the same person keeps one tint. */
export function tintIndex(id: string, buckets = 6): number {
  let hash = 0;
  for (let i = 0; i < id.length; i++) hash = (hash * 31 + id.charCodeAt(i)) | 0;
  return Math.abs(hash) % buckets;
}

export function memberDisplay(room: Room | undefined, userId: string): string {
  return room ? room.memberName(userId) : userId;
}

/** Group consecutive messages by sender within 5 minutes and the same day. */
export function continuesGroup(prev: MatrixEvent | undefined, event: MatrixEvent): boolean {
  if (!prev) return false;
  if (eventKind(prev) !== "message" || eventKind(event) !== "message") return false;
  if (prev.sender !== event.sender) return false;
  if (dayKey(prev.origin_server_ts) !== dayKey(event.origin_server_ts)) return false;
  return event.origin_server_ts - prev.origin_server_ts < 5 * 60_000;
}
