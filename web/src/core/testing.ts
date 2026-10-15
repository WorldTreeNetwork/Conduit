// Test doubles for the core: a scriptable in-memory transport.
import type { Transport, TransportRequest, TransportResponse } from "./http";

export interface FakeReply {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** Simulate a network failure instead of answering. */
  networkError?: boolean;
}

export type Handler = (request: TransportRequest & { path: string; query: URLSearchParams; json: unknown }) =>
  | FakeReply
  | Promise<FakeReply>;

/**
 * Routes are matched in registration order by method + path regex. Every
 * request is recorded so tests can assert on what went over the wire.
 */
export class FakeServer {
  readonly requests: (TransportRequest & { path: string; query: URLSearchParams; json: unknown })[] = [];
  private routes: { method: string; pattern: RegExp; handler: Handler; once: boolean }[] = [];

  on(method: string, pattern: RegExp, handler: Handler | FakeReply): this {
    this.routes.push({ method, pattern, handler: typeof handler === "function" ? handler : () => handler, once: false });
    return this;
  }

  once(method: string, pattern: RegExp, handler: Handler | FakeReply): this {
    // One-shot routes take precedence over permanent ones, first-in first-out.
    const firstPermanent = this.routes.findIndex((r) => !r.once);
    const at = firstPermanent < 0 ? this.routes.length : firstPermanent;
    this.routes.splice(at, 0, { method, pattern, handler: typeof handler === "function" ? handler : () => handler, once: true });
    return this;
  }

  requestsTo(pattern: RegExp): FakeServer["requests"] {
    return this.requests.filter((r) => pattern.test(r.path));
  }

  transport: Transport = async (request) => {
    const url = new URL(request.url);
    const json = typeof request.body === "string" ? JSON.parse(request.body) : undefined;
    const recorded = { ...request, path: url.pathname, query: url.searchParams, json };
    this.requests.push(recorded);
    const index = this.routes.findIndex((r) => r.method === request.method && r.pattern.test(url.pathname));
    if (index < 0) return reply({ status: 404, body: { errcode: "M_UNRECOGNIZED", error: "no fake route" } });
    const route = this.routes[index]!;
    if (route.once) this.routes.splice(index, 1);
    const result = await route.handler(recorded);
    if (result.networkError) throw new TypeError("Failed to fetch");
    if (request.signal?.aborted) throw new DOMException("aborted", "AbortError");
    return reply(result);
  };
}

function reply(result: FakeReply): TransportResponse {
  const headers = new Map(Object.entries(result.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    status: result.status ?? 200,
    headers: { get: (name) => headers.get(name.toLowerCase()) ?? null },
    text: async () => (result.body === undefined ? "" : JSON.stringify(result.body)),
  };
}

let counter = 0;
export function makeEvent(partial: Partial<import("./types").MatrixEvent> & { type: string }): import("./types").MatrixEvent {
  counter++;
  return {
    event_id: `$e${counter}`,
    sender: "@alice:test",
    origin_server_ts: 1_700_000_000_000 + counter,
    content: {},
    ...partial,
  };
}
