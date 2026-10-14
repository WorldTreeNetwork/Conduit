// Deterministic automation hook: window.__conduitClient.
//
// Lets e2e and manual debugging observe the client without scraping the DOM:
// sync state, the signed-in user, room summaries, the pending-send queue,
// and awaitIdle() which resolves once sync is live and nothing is in flight.
import type { MatrixClient, PendingEvent, RoomListEntry, SyncState } from "./core";
import { testHooksEnabled } from "./config";

export interface ConduitTestHook {
  readonly signedIn: boolean;
  readonly syncState: SyncState;
  readonly userId: string | null;
  readonly deviceId: string | null;
  rooms(): RoomListEntry[];
  pendingSends(): Pick<PendingEvent, "txnId" | "roomId" | "status" | "error" | "content">[];
  timeline(roomId: string): { eventId: string; type: string; sender: string; body?: string }[];
  awaitIdle(timeoutMs?: number): Promise<void>;
  /** Skip sync backoff now (same as the banner's "Retry now"). */
  retrySyncNow(): void;
}

declare global {
  interface Window {
    __conduitClient?: ConduitTestHook;
  }
}

export function installTestHook(client: MatrixClient | null): void {
  if (!testHooksEnabled || typeof window === "undefined") return;
  window.__conduitClient = {
    get signedIn() {
      return !!client && !client.loggedOutReason;
    },
    get syncState() {
      return client?.syncHealth.state ?? "stopped";
    },
    get userId() {
      return client?.userId ?? null;
    },
    get deviceId() {
      return client?.session.deviceId ?? null;
    },
    rooms: () => client?.roomList() ?? [],
    pendingSends: () =>
      (client?.sendQueue.all() ?? []).map(({ txnId, roomId, status, error, content }) => ({
        txnId,
        roomId,
        status,
        error,
        content,
      })),
    timeline: (roomId) =>
      (client?.getRoom(roomId)?.timeline ?? []).map((e) => ({
        eventId: e.event_id,
        type: e.type,
        sender: e.sender,
        body: typeof e.content.body === "string" ? e.content.body : undefined,
      })),
    awaitIdle: (timeoutMs) => (client ? client.awaitIdle(timeoutMs) : Promise.resolve()),
    retrySyncNow: () => client?.sync.retryNow(),
  };
}
