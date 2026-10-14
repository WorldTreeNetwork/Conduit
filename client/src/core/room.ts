// Room model: folds state events into current state and keeps an ordered,
// de-duplicated timeline. Historical (back-paginated) events never change
// current state; live events do.
import { aggregate, redactEvent, redactsOf, type Aggregations } from "./relations";
import type {
  JsonObject,
  MatrixEvent,
  Membership,
  RoomSummary,
  StrippedStateEvent,
} from "./types";

export interface RoomSnapshot {
  roomId: string;
  membership: Membership;
  state: MatrixEvent[];
  inviteState: StrippedStateEvent[];
  timeline: MatrixEvent[];
  prevBatch?: string;
  historyExhausted: boolean;
  unread: { notifications: number; highlights: number };
  summary: RoomSummary;
  readUpTo?: string;
}

/** How many timeline events to keep when persisting a room. */
export const SNAPSHOT_TIMELINE_LIMIT = 50;

export interface MemberInfo {
  userId: string;
  membership: string;
  displayName?: string;
  avatarUrl?: string;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export class Room {
  readonly roomId: string;
  membership: Membership = "join";
  readonly state = new Map<string, Map<string, MatrixEvent>>();
  inviteState: StrippedStateEvent[] = [];
  timeline: MatrixEvent[] = [];
  private readonly eventIds = new Set<string>();
  /** Token for the next /messages?dir=b request. */
  prevBatch: string | undefined;
  historyExhausted = false;
  unread = { notifications: 0, highlights: 0 };
  summary: RoomSummary = {};
  typing: string[] = [];
  /** userId -> eventId of their latest m.read receipt. */
  readonly receipts = new Map<string, { eventId: string; ts: number }>();
  /** The latest event this user has read (own receipt or local mark). */
  readUpTo: string | undefined;
  /** Thread replies fetched through /relations (older than the window). */
  readonly threadHistory = new Map<string, MatrixEvent[]>();
  /** Bumped on every timeline mutation; keys memoized views. */
  revision = 0;
  private aggregationCache: { revision: number; self: string; value: Aggregations } | undefined;

  constructor(roomId: string) {
    this.roomId = roomId;
  }

  // ---- state -------------------------------------------------------------

  applyState(event: MatrixEvent): void {
    if (event.state_key === undefined) return;
    let byKey = this.state.get(event.type);
    if (!byKey) {
      byKey = new Map();
      this.state.set(event.type, byKey);
    }
    byKey.set(event.state_key, event);
  }

  getState(type: string, stateKey = ""): MatrixEvent | undefined {
    return this.state.get(type)?.get(stateKey);
  }

  getStateContent(type: string, stateKey = ""): JsonObject | undefined {
    return this.getState(type, stateKey)?.content;
  }

  private strippedContent(type: string, stateKey = ""): JsonObject | undefined {
    return this.inviteState.find((e) => e.type === type && e.state_key === stateKey)?.content;
  }

  /** Current state if joined; stripped invite state otherwise. */
  private anyStateContent(type: string, stateKey = ""): JsonObject | undefined {
    return this.getStateContent(type, stateKey) ?? this.strippedContent(type, stateKey);
  }

  get explicitName(): string | undefined {
    return str(this.anyStateContent("m.room.name")?.name);
  }

  get topic(): string | undefined {
    return str(this.anyStateContent("m.room.topic")?.topic);
  }

  get canonicalAlias(): string | undefined {
    return str(this.anyStateContent("m.room.canonical_alias")?.alias);
  }

  get isEncrypted(): boolean {
    return !!this.getState("m.room.encryption");
  }

  get joinRule(): string | undefined {
    return str(this.anyStateContent("m.room.join_rules")?.join_rule);
  }

  get isPublic(): boolean {
    return this.joinRule === "public";
  }

  get creator(): string | undefined {
    return this.getState("m.room.create")?.sender;
  }

  members(): MemberInfo[] {
    const byKey = this.state.get("m.room.member");
    if (!byKey) return [];
    return [...byKey.values()].map((event) => ({
      userId: event.state_key ?? "",
      membership: str(event.content.membership) ?? "leave",
      displayName: str(event.content.displayname),
      avatarUrl: str(event.content.avatar_url),
    }));
  }

  member(userId: string): MemberInfo | undefined {
    const event = this.getState("m.room.member", userId);
    if (!event) return undefined;
    return {
      userId,
      membership: str(event.content.membership) ?? "leave",
      displayName: str(event.content.displayname),
      avatarUrl: str(event.content.avatar_url),
    };
  }

  /** Who invited `userId`, if they are invited (works for stripped state). */
  inviter(userId: string): string | undefined {
    const stripped = this.inviteState.find((e) => e.type === "m.room.member" && e.state_key === userId);
    if (stripped) return stripped.sender;
    return this.getState("m.room.member", userId)?.sender;
  }

  powerLevel(userId: string): number {
    const pl = this.getStateContent("m.room.power_levels");
    if (!pl) return userId === this.creator ? 100 : 0;
    const users = (pl.users ?? {}) as Record<string, unknown>;
    const level = users[userId];
    if (typeof level === "number") return level;
    return typeof pl.users_default === "number" ? pl.users_default : 0;
  }

  /**
   * Disambiguated display name for a member: spec "Calculating the display
   * name for a user". Falls back to the user ID.
   */
  memberName(userId: string): string {
    const info = this.member(userId);
    const name = info?.displayName;
    if (!name) return userId;
    const clash = this.members().some(
      (m) => m.userId !== userId && m.displayName === name && (m.membership === "join" || m.membership === "invite"),
    );
    return clash ? `${name} (${userId})` : name;
  }

  /**
   * Room display name per spec "Calculating the display name for a room":
   * m.room.name, then m.room.canonical_alias, then heroes.
   */
  displayName(selfUserId: string): string {
    const explicit = this.explicitName;
    if (explicit) return explicit;
    const alias = this.canonicalAlias;
    if (alias) return alias;

    if (this.membership === "invite") {
      const inviter = this.inviter(selfUserId);
      if (inviter) {
        const inviterName = str(
          this.inviteState.find((e) => e.type === "m.room.member" && e.state_key === inviter)?.content.displayname,
        );
        return inviterName ?? inviter;
      }
    }

    const others = this.members().filter((m) => m.userId !== selfUserId);
    const heroIds =
      this.summary["m.heroes"]?.filter((id) => id !== selfUserId) ??
      others
        .filter((m) => m.membership === "join" || m.membership === "invite")
        .map((m) => m.userId)
        .sort()
        .slice(0, 5);
    const activeCount =
      this.summary["m.joined_member_count"] !== undefined || this.summary["m.invited_member_count"] !== undefined
        ? (this.summary["m.joined_member_count"] ?? 0) + (this.summary["m.invited_member_count"] ?? 0) - 1
        : others.filter((m) => m.membership === "join" || m.membership === "invite").length;

    const heroName = (id: string) => this.member(id)?.displayName ?? id;
    if (activeCount <= 0) {
      const leftHeroes = others.filter((m) => m.membership === "leave" || m.membership === "ban").map((m) => m.userId);
      if (leftHeroes.length > 0) return `Empty room (was ${joinNames(leftHeroes.slice(0, 5).map(heroName), leftHeroes.length)})`;
      return "Empty room";
    }
    return joinNames(heroIds.map(heroName), activeCount);
  }

  // ---- timeline ----------------------------------------------------------

  hasEvent(eventId: string): boolean {
    return this.eventIds.has(eventId);
  }

  /** Append live events (from /sync), folding state as we go. */
  addLiveEvents(events: MatrixEvent[]): MatrixEvent[] {
    const added: MatrixEvent[] = [];
    for (const event of events) {
      if (!event?.event_id || this.eventIds.has(event.event_id)) continue;
      this.eventIds.add(event.event_id);
      this.timeline.push(event);
      if (event.state_key !== undefined) this.applyState(event);
      if (event.type === "m.room.redaction") this.applyRedaction(event);
      added.push(event);
    }
    if (added.length) this.revision++;
    return added;
  }

  /** Prepend events from /messages?dir=b (chunk is newest-first). */
  addHistoricalEvents(chunkNewestFirst: MatrixEvent[]): number {
    const older: MatrixEvent[] = [];
    for (const event of chunkNewestFirst) {
      if (!event?.event_id || this.eventIds.has(event.event_id)) continue;
      this.eventIds.add(event.event_id);
      older.push(event);
    }
    older.reverse();
    this.timeline = [...older, ...this.timeline];
    if (older.length) this.revision++;
    return older.length;
  }

  /** A limited sync means a gap: drop the old timeline, restart history. */
  resetTimeline(prevBatch: string | undefined): void {
    this.timeline = [];
    this.eventIds.clear();
    this.revision++;
    this.prevBatch = prevBatch;
    this.historyExhausted = false;
  }

  /** Replace a redacted event's content in place (timeline and state). */
  applyRedaction(redaction: MatrixEvent): void {
    const target = redactsOf(redaction);
    if (!target) return;
    const index = this.timeline.findIndex((e) => e.event_id === target);
    if (index >= 0) this.timeline[index] = redactEvent(this.timeline[index]!, redaction);
    for (const [rootId, list] of this.threadHistory) {
      this.threadHistory.set(
        rootId,
        list.map((e) => (e.event_id === target ? redactEvent(e, redaction) : e)),
      );
    }
    for (const byKey of this.state.values()) {
      for (const [key, event] of byKey) {
        if (event.event_id === target) byKey.set(key, redactEvent(event, redaction));
      }
    }
    this.revision++;
  }

  /** Relations over the loaded timeline (memoized per revision). */
  aggregations(selfUserId: string, extra: MatrixEvent[] = []): Aggregations {
    if (extra.length === 0 && this.aggregationCache?.revision === this.revision && this.aggregationCache.self === selfUserId) {
      return this.aggregationCache.value;
    }
    const value = aggregate(extra.length ? [...this.timeline, ...extra] : this.timeline, selfUserId);
    if (extra.length === 0) this.aggregationCache = { revision: this.revision, self: selfUserId, value };
    return value;
  }

  findEvent(eventId: string): MatrixEvent | undefined {
    const inTimeline = this.timeline.find((e) => e.event_id === eventId);
    if (inTimeline) return inTimeline;
    for (const list of this.threadHistory.values()) {
      const hit = list.find((e) => e.event_id === eventId);
      if (hit) return hit;
    }
    return undefined;
  }

  /** Every loaded reply in a thread, oldest first, de-duplicated. */
  threadReplies(rootId: string, selfUserId: string): MatrixEvent[] {
    const seen = new Map<string, MatrixEvent>();
    for (const e of this.threadHistory.get(rootId) ?? []) seen.set(e.event_id, e);
    for (const e of this.aggregations(selfUserId).threadEvents.get(rootId) ?? []) seen.set(e.event_id, e);
    return [...seen.values()].sort((a, b) => a.origin_server_ts - b.origin_server_ts);
  }

  addThreadHistory(rootId: string, events: MatrixEvent[]): void {
    const list = this.threadHistory.get(rootId) ?? [];
    const ids = new Set(list.map((e) => e.event_id));
    for (const e of events) if (e?.event_id && !ids.has(e.event_id)) list.push(e);
    this.threadHistory.set(rootId, list);
    this.revision++;
  }

  get lastEvent(): MatrixEvent | undefined {
    return this.timeline[this.timeline.length - 1];
  }

  /** Latest event a person would call "a message" (for previews). */
  lastMessage(): MatrixEvent | undefined {
    for (let i = this.timeline.length - 1; i >= 0; i--) {
      const event = this.timeline[i]!;
      const rel = (event.content["m.relates_to"] as { rel_type?: string } | undefined)?.rel_type;
      if (rel === "m.replace" || rel === "m.thread") continue;
      if (event.type === "m.room.message" && typeof event.content.body === "string") return event;
    }
    return undefined;
  }

  /**
   * Messages from other people after our read marker (or after our own
   * latest event). Complements the server's unread_notifications, which
   * counts only events push rules mark as notifying.
   */
  localUnread(selfUserId: string, cap = 99): number {
    let count = 0;
    for (let i = this.timeline.length - 1; i >= 0; i--) {
      const event = this.timeline[i]!;
      if (event.event_id === this.readUpTo || event.sender === selfUserId) break;
      const rel = (event.content["m.relates_to"] as { rel_type?: string } | undefined)?.rel_type;
      if ((event.type === "m.room.message" || event.type === "m.room.encrypted") && rel !== "m.replace") {
        count++;
        if (count >= cap) break;
      }
    }
    return count;
  }

  get lastActivityTs(): number {
    return this.lastEvent?.origin_server_ts ?? this.getState("m.room.create")?.origin_server_ts ?? 0;
  }

  // ---- persistence -------------------------------------------------------

  toSnapshot(): RoomSnapshot {
    const state: MatrixEvent[] = [];
    for (const byKey of this.state.values()) state.push(...byKey.values());
    const trimmed = this.timeline.length > SNAPSHOT_TIMELINE_LIMIT;
    return {
      roomId: this.roomId,
      membership: this.membership,
      state,
      inviteState: this.inviteState,
      timeline: this.timeline.slice(-SNAPSHOT_TIMELINE_LIMIT),
      // When trimmed, the stored prev_batch would skip the dropped events, so
      // history restarts from the stored window's oldest event instead.
      prevBatch: trimmed ? undefined : this.prevBatch,
      historyExhausted: trimmed ? false : this.historyExhausted,
      unread: this.unread,
      summary: this.summary,
      readUpTo: this.readUpTo,
    };
  }

  static fromSnapshot(snapshot: RoomSnapshot): Room {
    const room = new Room(snapshot.roomId);
    room.membership = snapshot.membership;
    for (const event of snapshot.state) room.applyState(event);
    room.inviteState = snapshot.inviteState ?? [];
    for (const event of snapshot.timeline) {
      room.eventIds.add(event.event_id);
      room.timeline.push(event);
    }
    room.prevBatch = snapshot.prevBatch;
    room.historyExhausted = snapshot.historyExhausted;
    room.unread = snapshot.unread ?? { notifications: 0, highlights: 0 };
    room.summary = snapshot.summary ?? {};
    room.readUpTo = snapshot.readUpTo;
    return room;
  }
}

function joinNames(names: string[], total: number): string {
  if (names.length === 0) return "Empty room";
  if (total > names.length) {
    const rest = total - names.length;
    return `${names.join(", ")} and ${rest} ${rest === 1 ? "other" : "others"}`;
  }
  if (names.length === 1) return names[0]!;
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}
