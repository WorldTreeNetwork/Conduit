import { AbortError } from "./errors";

/** Injectable time source. Unit tests use ManualClock to step time. */
export interface Clock {
  now(): number;
  /** Resolve after `ms`; reject with AbortError when `signal` aborts. */
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

export const realClock: Clock = {
  now: () => Date.now(),
  sleep(ms, signal) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(new AbortError());
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      const onAbort = () => {
        clearTimeout(timer);
        reject(new AbortError());
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  },
};

interface Sleeper {
  at: number;
  resolve: () => void;
  reject: (error: Error) => void;
}

/**
 * Deterministic clock: time moves only when a test calls advance(). Sleepers
 * whose deadline has passed are released in deadline order.
 */
export class ManualClock implements Clock {
  private time: number;
  private sleepers: Sleeper[] = [];

  constructor(start = 1_700_000_000_000) {
    this.time = start;
  }

  now(): number {
    return this.time;
  }

  sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(new AbortError());
      const sleeper: Sleeper = { at: this.time + Math.max(0, ms), resolve, reject };
      this.sleepers.push(sleeper);
      signal?.addEventListener(
        "abort",
        () => {
          this.sleepers = this.sleepers.filter((s) => s !== sleeper);
          reject(new AbortError());
        },
        { once: true },
      );
    });
  }

  /** Number of pending sleeps; lets tests wait for the code under test to park. */
  get pending(): number {
    return this.sleepers.length;
  }

  async advance(ms: number): Promise<void> {
    const target = this.time + ms;
    for (;;) {
      this.sleepers.sort((a, b) => a.at - b.at);
      const next = this.sleepers[0];
      if (!next || next.at > target) break;
      this.sleepers.shift();
      this.time = next.at;
      next.resolve();
      // Let the woken continuation run before releasing the next sleeper.
      await flushMicrotasks();
    }
    this.time = target;
    await flushMicrotasks();
  }
}

export async function flushMicrotasks(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}
