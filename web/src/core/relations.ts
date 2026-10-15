// Event relationships: edits (m.replace), reactions (m.annotation), replies
// (m.in_reply_to), threads (m.thread) and redactions, aggregated from the
// loaded timeline plus the server's bundled aggregations.
// https://spec.matrix.org/v1.19/client-server-api/#forming-relationships-between-events
import type { JsonObject, MatrixEvent } from "./types";

export interface RelatesTo {
  relType?: string;
  eventId?: string;
  key?: string;
  inReplyTo?: string;
  isFallingBack?: boolean;
}

export function relatesTo(event: { content: JsonObject }): RelatesTo {
  const rel = event.content["m.relates_to"];
  if (!rel || typeof rel !== "object") return {};
  const r = rel as Record<string, unknown>;
  const reply = r["m.in_reply_to"];
  return {
    relType: typeof r.rel_type === "string" ? r.rel_type : undefined,
    eventId: typeof r.event_id === "string" ? r.event_id : undefined,
    key: typeof r.key === "string" ? r.key : undefined,
    inReplyTo:
      reply && typeof reply === "object" && typeof (reply as Record<string, unknown>).event_id === "string"
        ? ((reply as Record<string, unknown>).event_id as string)
        : undefined,
    isFallingBack: r.is_falling_back === true,
  };
}

/** The event a redaction removes (v11 content.redacts, older top-level). */
export function redactsOf(event: MatrixEvent): string | undefined {
  const fromContent = event.content.redacts;
  if (typeof fromContent === "string") return fromContent;
  const top = (event as unknown as Record<string, unknown>).redacts;
  return typeof top === "string" ? top : undefined;
}

export interface ReactionGroup {
  key: string;
  count: number;
  senders: string[];
  /** Our own reaction event, so it can be redacted to un-react. */
  ownEventId?: string;
}

export interface ThreadSummary {
  count: number;
  latest?: MatrixEvent;
  participated: boolean;
}

export interface Aggregations {
  /** target event ID -> the latest valid replacement event. */
  edits: Map<string, MatrixEvent>;
  /** target event ID -> reactions grouped by key, in first-seen order. */
  reactions: Map<string, ReactionGroup[]>;
  /** thread root ID -> summary. */
  threads: Map<string, ThreadSummary>;
  /** thread root ID -> loaded thread replies in timeline order. */
  threadEvents: Map<string, MatrixEvent[]>;
  /** Events that are not shown as their own timeline row. */
  hidden: Set<string>;
}

export function isRedacted(event: MatrixEvent): boolean {
  return !!event.unsigned?.redacted_because;
}

/**
 * Aggregate relations over a timeline. Edits only count when sent by the
 * original sender (spec: replacement validity); redacted relations do not
 * count; bundled server aggregations fill in what is not loaded locally.
 */
export function aggregate(timeline: readonly MatrixEvent[], selfUserId: string): Aggregations {
  const byId = new Map(timeline.map((e) => [e.event_id, e]));
  const edits = new Map<string, MatrixEvent>();
  const reactionMap = new Map<string, Map<string, ReactionGroup>>();
  const threads = new Map<string, ThreadSummary>();
  const threadEvents = new Map<string, MatrixEvent[]>();
  const hidden = new Set<string>();

  for (const event of timeline) {
    if (event.type === "m.room.redaction") {
      hidden.add(event.event_id);
      continue;
    }
    const rel = relatesTo(event);
    if (rel.relType === "m.replace" && rel.eventId) {
      hidden.add(event.event_id);
      if (isRedacted(event)) continue;
      const original = byId.get(rel.eventId);
      if (original && (original.sender !== event.sender || original.type !== event.type)) continue;
      if (original && relatesTo(original).relType === "m.replace") continue;
      edits.set(rel.eventId, event);
    } else if (event.type === "m.reaction") {
      hidden.add(event.event_id);
      if (isRedacted(event) || rel.relType !== "m.annotation" || !rel.eventId || rel.key === undefined) continue;
      let groups = reactionMap.get(rel.eventId);
      if (!groups) {
        groups = new Map();
        reactionMap.set(rel.eventId, groups);
      }
      let group = groups.get(rel.key);
      if (!group) {
        group = { key: rel.key, count: 0, senders: [] };
        groups.set(rel.key, group);
      }
      if (group.senders.includes(event.sender)) continue;
      group.senders.push(event.sender);
      group.count++;
      if (event.sender === selfUserId) group.ownEventId = event.event_id;
    } else if (rel.relType === "m.thread" && rel.eventId) {
      hidden.add(event.event_id);
      const list = threadEvents.get(rel.eventId) ?? [];
      list.push(event);
      threadEvents.set(rel.eventId, list);
    }
  }

  for (const [rootId, replies] of threadEvents) {
    const visible = replies.filter((e) => !isRedacted(e));
    threads.set(rootId, {
      count: visible.length,
      latest: visible[visible.length - 1],
      participated: visible.some((e) => e.sender === selfUserId),
    });
  }

  // Bundled aggregations for events whose relations are not loaded.
  for (const event of timeline) {
    const bundled = event.unsigned?.["m.relations"] as Record<string, unknown> | undefined;
    if (!bundled || typeof bundled !== "object") continue;
    const replace = bundled["m.replace"] as MatrixEvent | undefined;
    if (replace?.event_id && !edits.has(event.event_id) && replace.sender === event.sender) {
      edits.set(event.event_id, replace);
    }
    const thread = bundled["m.thread"] as { count?: number; latest_event?: MatrixEvent; current_user_participated?: boolean } | undefined;
    if (thread && typeof thread.count === "number") {
      const local = threads.get(event.event_id);
      if (!local || local.count < thread.count) {
        threads.set(event.event_id, {
          count: thread.count,
          latest: local?.latest ?? thread.latest_event,
          participated: !!thread.current_user_participated || !!local?.participated,
        });
      }
    }
  }

  const reactions = new Map<string, ReactionGroup[]>();
  for (const [target, groups] of reactionMap) {
    const list = [...groups.values()].filter((g) => g.count > 0);
    if (list.length) reactions.set(target, list);
  }
  return { edits, reactions, threads, threadEvents, hidden };
}

/** The content to display for an event, after applying its latest edit. */
export function displayContent(event: MatrixEvent, aggregations: Aggregations): { content: JsonObject; edited: boolean } {
  if (isRedacted(event)) return { content: event.content, edited: false };
  const edit = aggregations.edits.get(event.event_id);
  const replacement = edit?.content["m.new_content"];
  if (edit && replacement && typeof replacement === "object") {
    return { content: replacement as JsonObject, edited: true };
  }
  return { content: event.content, edited: false };
}

/**
 * Strip a legacy reply fallback ("> <@user> quoted\n\n") from a body. The
 * spec removed fallbacks in v1.13 but older clients still send them.
 */
export function stripReplyFallback(body: string): string {
  if (!body.startsWith("> ")) return body;
  const lines = body.split("\n");
  let i = 0;
  while (i < lines.length && lines[i]!.startsWith(">")) i++;
  if (i < lines.length && lines[i] === "") i++;
  return lines.slice(i).join("\n");
}

/** Apply a redaction to a client-format event per the redaction algorithm (message events). */
export function redactEvent(event: MatrixEvent, redaction: MatrixEvent): MatrixEvent {
  const keep: Record<string, string[]> = {
    "m.room.member": ["membership", "join_authorised_via_users_server"],
    "m.room.create": [],
    "m.room.join_rules": ["join_rule", "allow"],
    "m.room.power_levels": ["ban", "events", "events_default", "invite", "kick", "redact", "state_default", "users", "users_default"],
    "m.room.history_visibility": ["history_visibility"],
  };
  const allowed = keep[event.type];
  const content: JsonObject = {};
  if (event.type === "m.room.create") Object.assign(content, event.content);
  else if (allowed) for (const k of allowed) if (k in event.content) content[k] = event.content[k];
  return {
    ...event,
    content,
    unsigned: { ...(event.unsigned ?? {}), redacted_because: redaction as unknown as JsonObject },
  };
}
