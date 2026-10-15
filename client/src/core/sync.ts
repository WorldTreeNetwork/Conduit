// The /sync loop: long-poll, since-token persistence, retry with backoff and
// an observable health state that drives the UI's connection banner.
// https://spec.matrix.org/v1.19/client-server-api/#syncing
import type { Clock } from "./clock";
import { AbortError, ConnectionError, MatrixError, describeError } from "./errors";
import type { HttpClient } from "./http";
import type { SyncResponse } from "./types";

/**
 * stopped      – not running
 * connecting   – first request in flight, nothing shown yet
 * live         – the last request succeeded; long-polling
 * reconnecting – the last request failed; waiting to retry
 * error        – fatal (token invalid); the loop has stopped
 */
export type SyncState = "stopped" | "connecting" | "live" | "reconnecting" | "error";

export interface SyncHealth {
  state: SyncState;
  /** True once at least one sync has been processed (live data or cache). */
  ready: boolean;
  failures: number;
  lastError?: string;
  /** Epoch ms of the next retry while reconnecting. */
  nextRetryAt?: number;
}

export interface SyncEngineOptions {
  http: HttpClient;
  clock: Clock;
  /** Inline filter JSON (or a filter ID). */
  filter?: string;
  longPollMs?: number;
  /** Backoff after the first failure; doubles to maxBackoffMs. */
  baseBackoffMs?: number;
  maxBackoffMs?: number;
  /** Process a response. Must apply it fully before resolving. */
  onSync: (response: SyncResponse, initial: boolean) => Promise<void> | void;
  onHealth: (health: SyncHealth) => void;
  /** M_UNKNOWN_TOKEN: the session is dead. */
  onLoggedOut: (error: MatrixError) => void;
}

export class SyncEngine {
  since: string | undefined;
  private health: SyncHealth = { state: "stopped", ready: false, failures: 0 };
  private controller: AbortController | undefined;
  private wake: AbortController | undefined;
  private running = false;
  private readonly options: Required<Pick<SyncEngineOptions, "longPollMs" | "baseBackoffMs" | "maxBackoffMs">> &
    SyncEngineOptions;
  private loopDone: Promise<void> | undefined;

  constructor(options: SyncEngineOptions) {
    this.options = {
      ...options,
      longPollMs: options.longPollMs ?? 30_000,
      baseBackoffMs: options.baseBackoffMs ?? 1_000,
      maxBackoffMs: options.maxBackoffMs ?? 15_000,
    };
  }

  get status(): SyncHealth {
    return this.health;
  }

  /** Mark cached data as displayable before the first network sync. */
  markReadyFromCache(): void {
    this.setHealth({ ...this.health, ready: true });
  }

  start(since?: string): void {
    if (this.running) return;
    this.since = since ?? this.since;
    this.running = true;
    this.controller = new AbortController();
    this.setHealth({ ...this.health, state: "connecting", failures: 0, lastError: undefined });
    this.loopDone = this.loop(this.controller.signal);
  }

  async stop(): Promise<void> {
    this.running = false;
    this.controller?.abort();
    this.wake?.abort();
    const done = this.loopDone;
    await done?.catch(() => undefined);
    // A start() may have raced in while we waited; it owns the state now.
    if (!this.running) this.setHealth({ ...this.health, state: "stopped", nextRetryAt: undefined });
  }

  /** Skip the remaining backoff (the banner's "Retry now", or `online`). */
  retryNow(): void {
    this.wake?.abort();
  }

  private async loop(signal: AbortSignal): Promise<void> {
    while (this.running && !signal.aborted) {
      const initial = this.since === undefined;
      // After a failure, poll with timeout=0 so "live" is re-established
      // as soon as the server answers rather than after a full long-poll.
      const timeout = initial || this.health.state !== "live" ? 0 : this.options.longPollMs;
      try {
        const response = await this.options.http.request<SyncResponse>("GET", "/_matrix/client/v3/sync", {
          query: {
            since: this.since,
            timeout,
            filter: this.options.filter,
            use_state_after: true,
          },
          signal,
          maxRetries: 0,
          timeoutMs: timeout + 20_000,
        });
        if (!this.running) return;
        if (typeof response.next_batch !== "string") {
          throw new Error("Malformed sync response: missing next_batch");
        }
        await this.options.onSync(response, initial);
        this.since = response.next_batch;
        this.setHealth({ state: "live", ready: true, failures: 0, lastError: undefined, nextRetryAt: undefined });
      } catch (error) {
        if (!this.running || signal.aborted || error instanceof AbortError) return;
        if (error instanceof MatrixError && error.isUnknownToken) {
          this.running = false;
          this.setHealth({ ...this.health, state: "error", lastError: describeError(error) });
          this.options.onLoggedOut(error);
          return;
        }
        const failures = this.health.failures + 1;
        let delay = Math.min(this.options.maxBackoffMs, this.options.baseBackoffMs * 2 ** (failures - 1));
        if (error instanceof MatrixError && error.retryAfterMs !== undefined) delay = error.retryAfterMs;
        // An invalid since token (e.g. server reset) cannot recover by
        // retrying: fall back to an initial sync.
        if (error instanceof MatrixError && error.httpStatus === 400 && this.since !== undefined) {
          this.since = undefined;
          delay = 0;
        }
        this.setHealth({
          ...this.health,
          state: "reconnecting",
          failures,
          lastError: error instanceof ConnectionError ? "Can't reach the server." : describeError(error),
          nextRetryAt: this.options.clock.now() + delay,
        });
        this.wake = new AbortController();
        const both = anySignal([signal, this.wake.signal]);
        try {
          await this.options.clock.sleep(delay, both);
        } catch {
          if (signal.aborted) return;
        }
      }
    }
  }

  private setHealth(next: SyncHealth): void {
    this.health = next;
    this.options.onHealth(next);
  }
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  const controller = new AbortController();
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort();
      break;
    }
    signal.addEventListener("abort", () => controller.abort(), { once: true });
  }
  return controller.signal;
}
