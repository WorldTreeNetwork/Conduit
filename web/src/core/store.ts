// Persistence seam. The core only needs string key/value storage; the browser
// uses localStorage, tests use MemoryStore.

export interface KeyValueStore {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export class MemoryStore implements KeyValueStore {
  readonly data = new Map<string, string>();
  get(key: string): string | null {
    return this.data.get(key) ?? null;
  }
  set(key: string, value: string): void {
    this.data.set(key, value);
  }
  remove(key: string): void {
    this.data.delete(key);
  }
}

export class LocalStorageStore implements KeyValueStore {
  constructor(private readonly prefix = "conduit:") {}
  get(key: string): string | null {
    try {
      return window.localStorage.getItem(this.prefix + key);
    } catch {
      return null;
    }
  }
  set(key: string, value: string): void {
    try {
      window.localStorage.setItem(this.prefix + key, value);
    } catch {
      // Quota or privacy mode: persistence is best-effort; the next start
      // falls back to an initial sync.
    }
  }
  remove(key: string): void {
    try {
      window.localStorage.removeItem(this.prefix + key);
    } catch {
      /* ignore */
    }
  }
}

export const KEYS = {
  session: "session",
  sync: "sync",
  pending: "pending",
} as const;

export function readJson<T>(store: KeyValueStore, key: string): T | undefined {
  const raw = store.get(key);
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as T;
  } catch {
    store.remove(key);
    return undefined;
  }
}

export function writeJson(store: KeyValueStore, key: string, value: unknown): void {
  store.set(key, JSON.stringify(value));
}
