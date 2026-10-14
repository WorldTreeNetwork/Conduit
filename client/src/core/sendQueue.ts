// Outgoing events with local echo.
//
// Every send gets a transaction ID up front and keeps it across retries,
// failures and restarts, so the server's (user, device, txnId) idempotency
// guarantees a retried PUT never produces a duplicate event.
// https://spec.matrix.org/v1.19/client-server-api/#transaction-identifiers
import type { Clock } from "./clock";
import type { CryptoBackend } from "./crypto";
import { describeError } from "./errors";
import { enc, type HttpClient } from "./http";
import type { JsonObject } from "./types";

export type SendStatus = "queued" | "sending" | "sent" | "failed";

export interface PendingEvent {
  txnId: string;
  roomId: string;
  type: string;
  content: JsonObject;
  status: SendStatus;
  createdTs: number;
  /** Set once the server has accepted the event. */
  eventId?: string;
  error?: string;
  attempts: number;
}

export interface SendQueueOptions {
  http: HttpClient;
  clock: Clock;
  crypto: CryptoBackend;
  onChange: () => void;
  /** Called with the persisted form whenever the queue changes. */
  persist?: (items: PendingEvent[]) => void;
  /** Is this event already in the room's timeline (remote echo arrived)? */
  hasRemoteEcho: (roomId: string, eventId: string) => boolean;
  isRoomEncrypted?: (roomId: string) => boolean;
}

export class SendQueue {
  private items: PendingEvent[] = [];
  private readonly busyRooms = new Set<string>();
  private counter = 0;
  private readonly options: SendQueueOptions;
  private stopped = false;

  constructor(options: SendQueueOptions) {
    this.options = options;
  }

  /** Restore persisted sends. Anything mid-flight is queued again. */
  restore(items: PendingEvent[]): void {
    this.items = items
      .filter((item) => item.status !== "sent")
      .map((item) => ({ ...item, status: item.status === "sending" ? "queued" : item.status }));
    this.changed();
  }

  start(): void {
    this.stopped = false;
    for (const roomId of new Set(this.items.map((i) => i.roomId))) void this.pump(roomId);
  }

  stop(): void {
    this.stopped = true;
  }

  all(): readonly PendingEvent[] {
    return this.items;
  }

  forRoom(roomId: string): PendingEvent[] {
    return this.items.filter((item) => item.roomId === roomId);
  }

  get busy(): boolean {
    return this.items.some((item) => item.status === "queued" || item.status === "sending");
  }

  newTxnId(): string {
    this.counter += 1;
    const random = Math.random().toString(36).slice(2, 8);
    return `c${this.options.clock.now()}.${this.counter}.${random}`;
  }

  enqueue(roomId: string, type: string, content: JsonObject): PendingEvent {
    const item: PendingEvent = {
      txnId: this.newTxnId(),
      roomId,
      type,
      content,
      status: "queued",
      createdTs: this.options.clock.now(),
      attempts: 0,
    };
    this.items.push(item);
    this.changed();
    void this.pump(roomId);
    return item;
  }

  retry(txnId: string): void {
    const item = this.items.find((i) => i.txnId === txnId);
    if (!item || item.status !== "failed") return;
    item.status = "queued";
    item.error = undefined;
    this.changed();
    void this.pump(item.roomId);
  }

  /** Drop a send that has not been accepted by the server. */
  discard(txnId: string): void {
    const item = this.items.find((i) => i.txnId === txnId);
    if (!item || item.status === "sending" || item.status === "sent") return;
    this.items = this.items.filter((i) => i !== item);
    this.changed();
  }

  /**
   * A remote event arrived via /sync. Drop the matching local echo, matched
   * by event ID or by unsigned.transaction_id.
   */
  reconcile(eventId: string, txnId?: string): void {
    const before = this.items.length;
    this.items = this.items.filter(
      (item) => !(item.eventId === eventId || (txnId !== undefined && item.txnId === txnId)),
    );
    if (this.items.length !== before) this.changed();
  }

  /** Forget everything that targets a room (e.g. after leaving it). */
  dropRoom(roomId: string): void {
    const before = this.items.length;
    this.items = this.items.filter((item) => item.roomId !== roomId || item.status === "sending");
    if (this.items.length !== before) this.changed();
  }

  /** Sends are serialized per room so the timeline order matches intent. */
  private async pump(roomId: string): Promise<void> {
    if (this.busyRooms.has(roomId) || this.stopped) return;
    this.busyRooms.add(roomId);
    try {
      for (;;) {
        if (this.stopped) return;
        const item = this.items.find((i) => i.roomId === roomId && i.status === "queued");
        if (!item) return;
        await this.sendOne(item);
      }
    } finally {
      this.busyRooms.delete(roomId);
    }
  }

  private async sendOne(item: PendingEvent): Promise<void> {
    item.status = "sending";
    item.attempts += 1;
    this.changed();
    try {
      let type = item.type;
      let content = item.content;
      if (this.options.isRoomEncrypted?.(item.roomId)) {
        ({ type, content } = await this.options.crypto.encryptRoomEvent(item.roomId, type, content));
      }
      const response = await this.options.http.request<{ event_id?: string }>(
        "PUT",
        `/_matrix/client/v3/rooms/${enc(item.roomId)}/send/${enc(type)}/${enc(item.txnId)}`,
        { body: content, maxRetries: 2 },
      );
      if (!this.items.includes(item)) return;
      item.status = "sent";
      item.eventId = response.event_id;
      item.error = undefined;
      if (item.eventId && this.options.hasRemoteEcho(item.roomId, item.eventId)) {
        this.items = this.items.filter((i) => i !== item);
      }
    } catch (error) {
      if (!this.items.includes(item)) return;
      item.status = "failed";
      item.error = describeError(error);
    }
    this.changed();
  }

  private changed(): void {
    this.options.persist?.(this.items);
    this.options.onChange();
  }
}
