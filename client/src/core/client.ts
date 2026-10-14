// MatrixClient: the framework-free facade the UI talks to. It owns the HTTP
// client, the sync engine, the room models and the send queue, and exposes a
// tiny observable (subscribe + version) for React's useSyncExternalStore.
import * as auth from "./auth";
import { realClock, type Clock } from "./clock";
import { noCrypto, type CryptoBackend } from "./crypto";
import { MatrixError, describeError } from "./errors";
import { enc, HttpClient, type Transport } from "./http";
import { Room, type RoomSnapshot } from "./room";
import { SendQueue, type PendingEvent } from "./sendQueue";
import { KEYS, readJson, writeJson, type KeyValueStore } from "./store";
import { SyncEngine, type SyncHealth } from "./sync";
import type { JsonObject, MatrixEvent, MessagesResponse, Session, SyncResponse } from "./types";

/** Filter sent with every /sync. Inline JSON keeps the since token valid. */
export const SYNC_FILTER = JSON.stringify({
  room: {
    timeline: { limit: 30 },
    state: { lazy_load_members: false },
  },
});

interface SyncSnapshot {
  version: 1;
  userId: string;
  since: string;
  rooms: RoomSnapshot[];
}

export interface RoomListEntry {
  roomId: string;
  name: string;
  membership: Room["membership"];
  unread: number;
  highlights: number;
  preview?: { sender: string; body: string; ts: number };
  lastActivityTs: number;
  inviter?: string;
  topic?: string;
}

export interface ClientOptions {
  session: Session;
  store: KeyValueStore;
  transport?: Transport;
  clock?: Clock;
  crypto?: CryptoBackend;
  /** Sync backoff tuning (tests shorten it). */
  syncBackoffMs?: number;
  longPollMs?: number;
}

type Listener = () => void;

export class MatrixClient {
  readonly session: Session;
  readonly http: HttpClient;
  readonly clock: Clock;
  readonly rooms = new Map<string, Room>();
  readonly sendQueue: SendQueue;
  readonly sync: SyncEngine;
  readonly crypto: CryptoBackend;
  private readonly store: KeyValueStore;
  private readonly listeners = new Set<Listener>();
  private version = 0;
  private health: SyncHealth;
  private inflight = 0;
  private readonly lastReceipt = new Map<string, string>();
  private readonly roomWaiters = new Set<() => void>();
  /** Set when the server rejects our token. */
  loggedOutReason: string | undefined;
  onLoggedOut?: (reason: string) => void;

  constructor(options: ClientOptions) {
    this.session = options.session;
    this.store = options.store;
    this.clock = options.clock ?? realClock;
    this.crypto = options.crypto ?? noCrypto;
    this.http = new HttpClient({
      baseUrl: options.session.homeserverUrl,
      accessToken: options.session.accessToken,
      transport: options.transport,
      clock: this.clock,
    });
    this.http.onUnknownToken = (error) => this.handleLoggedOut(error);
    this.sendQueue = new SendQueue({
      http: this.http,
      clock: this.clock,
      crypto: this.crypto,
      onChange: () => this.emit(),
      persist: (items) => writeJson(this.store, KEYS.pending, items),
      hasRemoteEcho: (roomId, eventId) => !!this.rooms.get(roomId)?.hasEvent(eventId),
      isRoomEncrypted: (roomId) => !!this.rooms.get(roomId)?.isEncrypted,
    });
    this.sync = new SyncEngine({
      http: this.http,
      clock: this.clock,
      filter: SYNC_FILTER,
      baseBackoffMs: options.syncBackoffMs,
      longPollMs: options.longPollMs,
      onSync: (response, initial) => this.processSync(response, initial),
      onHealth: (health) => {
        this.health = this.loggedOutReason ? { ...health, state: "error", lastError: this.loggedOutReason } : health;
        this.emit();
      },
      onLoggedOut: (error) => this.handleLoggedOut(error),
    });
    this.health = this.sync.status;
  }

  // ---- observable --------------------------------------------------------

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getVersion = (): number => this.version;

  private emit(): void {
    this.version++;
    for (const waiter of [...this.roomWaiters]) waiter();
    for (const listener of [...this.listeners]) listener();
  }

  get syncHealth(): SyncHealth {
    return this.health;
  }

  get userId(): string {
    return this.session.userId;
  }

  /** In-flight user operations (create, join, paginate...). */
  get busyOperations(): number {
    return this.inflight;
  }

  private async track<T>(work: () => Promise<T>): Promise<T> {
    this.inflight++;
    this.emit();
    try {
      return await work();
    } finally {
      this.inflight--;
      this.emit();
    }
  }

  // ---- lifecycle ---------------------------------------------------------

  /** Restore cached rooms + since token, then start syncing. */
  start(): void {
    const snapshot = readJson<SyncSnapshot>(this.store, KEYS.sync);
    let since: string | undefined;
    if (snapshot?.version === 1 && snapshot.userId === this.session.userId) {
      for (const room of snapshot.rooms) this.rooms.set(room.roomId, Room.fromSnapshot(room));
      since = snapshot.since;
      this.sync.markReadyFromCache();
    }
    this.sendQueue.restore(readJson<PendingEvent[]>(this.store, KEYS.pending) ?? []);
    this.sendQueue.start();
    this.sync.start(since);
    this.emit();
  }

  async stop(): Promise<void> {
    this.sendQueue.stop();
    await this.sync.stop();
  }

  /** Sign out on the server (best effort) and wipe local state. */
  async logout(): Promise<void> {
    await this.stop();
    try {
      await auth.logout(this.http);
    } catch (error) {
      // An already-invalid token is a successful logout from our side.
      if (!(error instanceof MatrixError)) {
        // Network failure: the device stays on the server; the person can
        // remove it from another session. Local wipe still proceeds.
      }
    }
    clearStoredSession(this.store);
  }

  private handleLoggedOut(error: MatrixError): void {
    if (this.loggedOutReason) return;
    this.loggedOutReason = describeError(error);
    this.health = { ...this.health, state: "error", lastError: this.loggedOutReason };
    void this.stop();
    clearStoredSession(this.store);
    this.emit();
    this.onLoggedOut?.(this.loggedOutReason);
  }

  // ---- sync processing ---------------------------------------------------

  private getOrCreateRoom(roomId: string): Room {
    let room = this.rooms.get(roomId);
    if (!room) {
      room = new Room(roomId);
      this.rooms.set(roomId, room);
    }
    return room;
  }

  async processSync(response: SyncResponse, initial: boolean): Promise<void> {
    await this.crypto.receiveSyncChanges(response);
    if (initial) this.rooms.clear();
    const rooms = response.rooms ?? {};

    for (const [roomId, joined] of Object.entries(rooms.join ?? {})) {
      const room = this.getOrCreateRoom(roomId);
      room.membership = "join";
      room.inviteState = [];
      if (joined.summary) room.summary = { ...room.summary, ...joined.summary };
      const timeline = joined.timeline ?? {};
      if (timeline.limited) {
        room.resetTimeline(timeline.prev_batch);
      } else if (room.timeline.length === 0 && room.prevBatch === undefined && !room.historyExhausted) {
        room.prevBatch = timeline.prev_batch;
      }
      for (const event of joined.state?.events ?? []) room.applyState(event);
      const added = room.addLiveEvents(await this.decryptAll(timeline.events ?? []));
      for (const event of added) {
        if (event.sender === this.userId) {
          this.sendQueue.reconcile(event.event_id, event.unsigned?.transaction_id);
        }
      }
      if (joined.unread_notifications) {
        room.unread = {
          notifications: joined.unread_notifications.notification_count ?? 0,
          highlights: joined.unread_notifications.highlight_count ?? 0,
        };
      }
      for (const event of joined.ephemeral?.events ?? []) this.applyEphemeral(room, event);
    }

    for (const [roomId, invited] of Object.entries(rooms.invite ?? {})) {
      const room = this.getOrCreateRoom(roomId);
      room.membership = "invite";
      room.inviteState = invited.invite_state?.events ?? [];
    }

    for (const roomId of Object.keys(rooms.leave ?? {})) {
      this.rooms.delete(roomId);
      this.sendQueue.dropRoom(roomId);
    }

    this.persistSnapshot(response.next_batch);
    this.emit();
  }

  private applyEphemeral(room: Room, event: { type: string; content: JsonObject }): void {
    if (event.type === "m.typing") {
      const ids = event.content.user_ids;
      room.typing = Array.isArray(ids) ? ids.filter((id): id is string => typeof id === "string") : [];
    } else if (event.type === "m.receipt") {
      for (const [eventId, byType] of Object.entries(event.content)) {
        const reads = (byType as JsonObject)?.["m.read"] as Record<string, { ts?: number }> | undefined;
        for (const [userId, receipt] of Object.entries(reads ?? {})) {
          room.receipts.set(userId, { eventId, ts: receipt?.ts ?? 0 });
          if (userId === this.userId) room.readUpTo = eventId;
        }
      }
    }
  }

  private async decryptAll(events: MatrixEvent[]): Promise<MatrixEvent[]> {
    if (!this.crypto.enabled) return events;
    const out: MatrixEvent[] = [];
    for (const event of events) {
      if (event.type === "m.room.encrypted") {
        out.push((await this.crypto.decryptEvent(event)) ?? event);
      } else {
        out.push(event);
      }
    }
    return out;
  }

  private persistSnapshot(since: string): void {
    const snapshot: SyncSnapshot = {
      version: 1,
      userId: this.userId,
      since,
      rooms: [...this.rooms.values()].map((room) => room.toSnapshot()),
    };
    writeJson(this.store, KEYS.sync, snapshot);
  }

  // ---- queries -----------------------------------------------------------

  roomList(): RoomListEntry[] {
    const entries: RoomListEntry[] = [];
    for (const room of this.rooms.values()) {
      const last = room.lastMessage();
      const pending = this.sendQueue.forRoom(room.roomId);
      const lastPending = pending[pending.length - 1];
      let preview: RoomListEntry["preview"];
      if (lastPending && (!last || lastPending.createdTs >= last.origin_server_ts)) {
        preview = { sender: this.userId, body: String(lastPending.content.body ?? ""), ts: lastPending.createdTs };
      } else if (last) {
        preview = { sender: last.sender, body: String(last.content.body), ts: last.origin_server_ts };
      }
      entries.push({
        roomId: room.roomId,
        name: room.displayName(this.userId),
        membership: room.membership,
        unread: Math.max(room.unread.notifications, room.localUnread(this.userId)),
        highlights: room.unread.highlights,
        preview,
        lastActivityTs: Math.max(room.lastActivityTs, preview?.ts ?? 0),
        inviter: room.membership === "invite" ? room.inviter(this.userId) : undefined,
        topic: room.topic,
      });
    }
    return entries.sort((a, b) => {
      if (a.membership === "invite" && b.membership !== "invite") return -1;
      if (b.membership === "invite" && a.membership !== "invite") return 1;
      return b.lastActivityTs - a.lastActivityTs || a.name.localeCompare(b.name);
    });
  }

  getRoom(roomId: string): Room | undefined {
    return this.rooms.get(roomId);
  }

  /** Resolve once `predicate` holds after some change (or immediately). */
  waitFor(predicate: () => boolean, timeoutMs = 30_000): Promise<void> {
    if (predicate()) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const check = () => {
        if (predicate()) {
          cleanup();
          resolve();
        }
      };
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("Timed out waiting for the server to confirm."));
      }, timeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        this.roomWaiters.delete(check);
      };
      this.roomWaiters.add(check);
    });
  }

  private waitForMembership(roomId: string, membership: Room["membership"] | "gone"): Promise<void> {
    return this.waitFor(() => {
      const room = this.rooms.get(roomId);
      return membership === "gone" ? !room : room?.membership === membership;
    });
  }

  // ---- actions -----------------------------------------------------------

  sendMessage(roomId: string, body: string, msgtype: "m.text" | "m.emote" | "m.notice" = "m.text"): PendingEvent {
    return this.sendQueue.enqueue(roomId, "m.room.message", { msgtype, body });
  }

  retrySend(txnId: string): void {
    this.sendQueue.retry(txnId);
  }

  discardSend(txnId: string): void {
    this.sendQueue.discard(txnId);
  }

  createRoom(options: { name?: string; topic?: string; visibility: "public" | "private"; invite?: string[] }): Promise<string> {
    return this.track(async () => {
      const body: JsonObject = {
        preset: options.visibility === "public" ? "public_chat" : "private_chat",
        visibility: options.visibility,
      };
      if (options.name?.trim()) body.name = options.name.trim();
      if (options.topic?.trim()) body.topic = options.topic.trim();
      if (options.invite?.length) body.invite = options.invite;
      const response = await this.http.request<{ room_id: string }>("POST", "/_matrix/client/v3/createRoom", {
        body,
        maxRetries: 0,
      });
      await this.waitForMembership(response.room_id, "join");
      return response.room_id;
    });
  }

  joinRoom(roomIdOrAlias: string): Promise<string> {
    return this.track(async () => {
      const response = await this.http.request<{ room_id: string }>(
        "POST",
        `/_matrix/client/v3/join/${enc(roomIdOrAlias.trim())}`,
        { body: {}, maxRetries: 1 },
      );
      await this.waitForMembership(response.room_id, "join");
      return response.room_id;
    });
  }

  leaveRoom(roomId: string): Promise<void> {
    return this.track(async () => {
      await this.http.request("POST", `/_matrix/client/v3/rooms/${enc(roomId)}/leave`, { body: {}, maxRetries: 1 });
      // Remove immediately; the leave block in the next sync is idempotent.
      this.rooms.delete(roomId);
      this.sendQueue.dropRoom(roomId);
      this.emit();
    });
  }

  /** Declining an invite is a leave (spec: rejecting an invite). */
  rejectInvite(roomId: string): Promise<void> {
    return this.leaveRoom(roomId);
  }

  acceptInvite(roomId: string): Promise<string> {
    return this.joinRoom(roomId);
  }

  invite(roomId: string, userId: string): Promise<void> {
    return this.track(async () => {
      await this.http.request("POST", `/_matrix/client/v3/rooms/${enc(roomId)}/invite`, {
        body: { user_id: userId.trim() },
        maxRetries: 1,
      });
      await this.waitFor(() => this.rooms.get(roomId)?.member(userId.trim())?.membership === "invite", 15_000).catch(
        () => undefined,
      );
    });
  }

  /**
   * Load older events. Uses the room's prev_batch; when the token was lost
   * (trimmed cache) it pages from the live end and skips known events.
   */
  paginateBack(roomId: string, limit = 30): Promise<number> {
    return this.track(async () => {
      const room = this.rooms.get(roomId);
      if (!room || room.historyExhausted) return 0;
      let from = room.prevBatch;
      for (let page = 0; page < 20; page++) {
        const response = await this.http.request<MessagesResponse>(
          "GET",
          `/_matrix/client/v3/rooms/${enc(roomId)}/messages`,
          { query: { dir: "b", limit, from } },
        );
        const chunk = await this.decryptAll(response.chunk ?? []);
        const added = room.addHistoricalEvents(chunk);
        const end = response.end;
        if (!end || chunk.length === 0) {
          room.historyExhausted = true;
          room.prevBatch = undefined;
          this.emit();
          return added;
        }
        room.prevBatch = end;
        from = end;
        if (added > 0) {
          this.emit();
          return added;
        }
      }
      this.emit();
      return 0;
    });
  }

  /** Send an m.read receipt for the latest event, at most once per event. */
  async markRead(roomId: string): Promise<void> {
    const room = this.rooms.get(roomId);
    const last = room?.lastEvent;
    if (!room || !last || this.lastReceipt.get(roomId) === last.event_id) return;
    this.lastReceipt.set(roomId, last.event_id);
    const changed = room.readUpTo !== last.event_id || room.unread.notifications > 0 || room.unread.highlights > 0;
    room.readUpTo = last.event_id;
    room.unread = { notifications: 0, highlights: 0 };
    if (changed) this.emit();
    try {
      await this.http.request(
        "POST",
        `/_matrix/client/v3/rooms/${enc(roomId)}/receipt/m.read/${enc(last.event_id)}`,
        { body: {}, maxRetries: 1 },
      );
    } catch {
      this.lastReceipt.delete(roomId);
    }
  }

  getProfile(userId: string): Promise<{ displayname?: string; avatar_url?: string }> {
    return this.http.request("GET", `/_matrix/client/v3/profile/${enc(userId)}`, { maxRetries: 1 });
  }

  setDisplayName(name: string): Promise<void> {
    return this.track(async () => {
      const displayname = name.trim();
      await this.http.request("PUT", `/_matrix/client/v3/profile/${enc(this.userId)}/displayname`, {
        body: { displayname },
        maxRetries: 1,
      });
      // Servers SHOULD propagate the change into each joined room's
      // m.room.member event; not all do. Update rooms whose member event
      // still carries the old name so other people see the new one. A
      // server that did propagate makes these no-op state updates.
      for (const room of this.rooms.values()) {
        if (room.membership !== "join") continue;
        const member = room.getStateContent("m.room.member", this.userId);
        if (!member || member.membership !== "join" || member.displayname === (displayname || undefined)) continue;
        const content: JsonObject = { ...member, membership: "join" };
        if (displayname) content.displayname = displayname;
        else delete content.displayname;
        await this.http
          .request(
            "PUT",
            `/_matrix/client/v3/rooms/${enc(room.roomId)}/state/m.room.member/${enc(this.userId)}`,
            { body: content, maxRetries: 1 },
          )
          .catch(() => undefined);
      }
    });
  }

  joinedMembers(roomId: string): Promise<Record<string, { display_name?: string; avatar_url?: string }>> {
    return this.http
      .request<{ joined?: Record<string, { display_name?: string; avatar_url?: string }> }>(
        "GET",
        `/_matrix/client/v3/rooms/${enc(roomId)}/joined_members`,
      )
      .then((body) => body.joined ?? {});
  }

  // ---- automation ----------------------------------------------------------

  /** True when nothing is in flight beyond the idle long-poll. */
  get isIdle(): boolean {
    return (
      this.health.state === "live" && this.health.ready && !this.sendQueue.busy && this.inflight === 0
    );
  }

  awaitIdle(timeoutMs = 20_000): Promise<void> {
    return this.waitFor(() => this.isIdle, timeoutMs);
  }
}

// ---- session persistence ----------------------------------------------------

export function loadStoredSession(store: KeyValueStore): Session | undefined {
  const session = readJson<Session>(store, KEYS.session);
  if (!session?.accessToken || !session.userId || !session.homeserverUrl) return undefined;
  return session;
}

export function saveSession(store: KeyValueStore, session: Session): void {
  writeJson(store, KEYS.session, session);
}

export function clearStoredSession(store: KeyValueStore): void {
  store.remove(KEYS.session);
  store.remove(KEYS.sync);
  store.remove(KEYS.pending);
}
