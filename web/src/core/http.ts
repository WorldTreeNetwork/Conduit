import type { Clock } from "./clock";
import { AbortError, ConnectionError, MatrixError } from "./errors";

/** The wire. Injectable so unit tests can script responses. */
export interface TransportRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Blob | ArrayBuffer;
  signal?: AbortSignal;
}

export interface TransportResponse {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  blob?(): Promise<Blob>;
}

export type Transport = (request: TransportRequest) => Promise<TransportResponse>;

export const fetchTransport: Transport = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    body: request.body,
    signal: request.signal,
  });
  return response;
};

export type Query = Record<string, string | number | boolean | undefined>;

export interface RequestOptions {
  query?: Query;
  body?: unknown;
  /** Send bytes instead of JSON (media upload). */
  raw?: { data: Blob | ArrayBuffer; contentType: string };
  /** Send the access token. Default true. */
  auth?: boolean;
  signal?: AbortSignal;
  /** Retries for 429 / 5xx / network failures. Default 2 (3 attempts). */
  maxRetries?: number;
  /** Abort the attempt after this many ms (network timeout). */
  timeoutMs?: number;
}

export interface HttpOptions {
  baseUrl: string;
  accessToken?: string;
  transport?: Transport;
  clock: Clock;
  /** First retry delay; doubles each attempt. */
  baseBackoffMs?: number;
  maxBackoffMs?: number;
}

/** Percent-encode one path segment (room IDs contain '!' and ':'). */
export function enc(segment: string): string {
  return encodeURIComponent(segment);
}

export class HttpClient {
  baseUrl: string;
  accessToken: string | undefined;
  private readonly transport: Transport;
  private readonly clock: Clock;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  /** Fires on M_UNKNOWN_TOKEN that refreshing could not cure. */
  onUnknownToken?: (error: MatrixError) => void;
  /**
   * Called on M_UNKNOWN_TOKEN with soft_logout: true. Returns true when a
   * new access token is in place, so the request is retried once.
   */
  refreshAccessToken?: () => Promise<boolean>;
  private refreshing: Promise<boolean> | undefined;

  /** One refresh at a time; concurrent 401s share it. */
  private refreshOnce(): Promise<boolean> {
    if (!this.refreshAccessToken) return Promise.resolve(false);
    if (!this.refreshing) {
      this.refreshing = this.refreshAccessToken()
        .catch(() => false)
        .finally(() => {
          this.refreshing = undefined;
        });
    }
    return this.refreshing;
  }

  constructor(options: HttpOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.accessToken = options.accessToken;
    this.transport = options.transport ?? fetchTransport;
    this.clock = options.clock;
    this.baseBackoffMs = options.baseBackoffMs ?? 500;
    this.maxBackoffMs = options.maxBackoffMs ?? 10_000;
  }

  url(path: string, query?: Query): string {
    let url = `${this.baseUrl}${path}`;
    if (query) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) params.set(key, String(value));
      }
      const text = params.toString();
      if (text) url += `?${text}`;
    }
    return url;
  }

  /**
   * One Matrix API call with rate-limit/backoff handling. 429 honours the
   * server's Retry-After / retry_after_ms; 5xx and connection failures back
   * off exponentially. 4xx Matrix errors are thrown immediately.
   */
  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    const maxRetries = options.maxRetries ?? 2;
    let attempt = 0;
    let refreshed = false;
    for (;;) {
      try {
        return await this.once<T>(method, path, options);
      } catch (error) {
        if (options.signal?.aborted || error instanceof AbortError) throw error;
        if (
          error instanceof MatrixError &&
          error.isUnknownToken &&
          options.auth !== false &&
          !refreshed &&
          this.refreshAccessToken
        ) {
          refreshed = true;
          const tokenBeforeFailure = this.accessToken;
          // Another request may already have rotated the token.
          if (error.isSoftLogout && (await this.refreshOnce())) continue;
          if (this.accessToken !== tokenBeforeFailure) continue;
          this.onUnknownToken?.(error);
          throw error;
        }
        if (error instanceof MatrixError && error.isUnknownToken && refreshed && options.auth !== false) {
          this.onUnknownToken?.(error);
          throw error;
        }
        const retryable =
          error instanceof ConnectionError || (error instanceof MatrixError && error.isTransient);
        if (!retryable || attempt >= maxRetries) throw error;
        const delay =
          error instanceof MatrixError && error.retryAfterMs !== undefined
            ? error.retryAfterMs
            : Math.min(this.maxBackoffMs, this.baseBackoffMs * 2 ** attempt);
        attempt++;
        await this.clock.sleep(delay, options.signal);
      }
    }
  }

  /** Authenticated binary download (v1 media). */
  async download(path: string, query?: Query, signal?: AbortSignal): Promise<Blob> {
    const headers: Record<string, string> = {};
    if (this.accessToken) headers.Authorization = `Bearer ${this.accessToken}`;
    let response: TransportResponse;
    try {
      response = await this.transport({ method: "GET", url: this.url(path, query), headers, signal });
    } catch (cause) {
      if (signal?.aborted) throw new AbortError();
      throw new ConnectionError(`GET ${path} failed: ${String(cause)}`, cause);
    }
    if (response.status < 200 || response.status >= 300) {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(await response.text()) as Record<string, unknown>;
      } catch {
        /* not JSON */
      }
      throw new MatrixError(response.status, body, response.headers.get("Retry-After"));
    }
    if (!response.blob) throw new Error("This transport cannot download binary content.");
    return response.blob();
  }

  private async once<T>(method: string, path: string, options: RequestOptions): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    let body: string | Blob | ArrayBuffer | undefined = options.raw?.data;
    if (options.raw) {
      headers["Content-Type"] = options.raw.contentType || "application/octet-stream";
    } else if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    if (options.auth !== false && this.accessToken) {
      headers.Authorization = `Bearer ${this.accessToken}`;
    }
    const controller = new AbortController();
    const relay = () => controller.abort();
    options.signal?.addEventListener("abort", relay, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (options.timeoutMs !== undefined) {
      timer = setTimeout(() => controller.abort(), options.timeoutMs);
    }
    let response: TransportResponse;
    let text: string;
    try {
      response = await this.transport({
        method,
        url: this.url(path, options.query),
        headers,
        body,
        signal: controller.signal,
      });
      text = await response.text();
    } catch (cause) {
      if (options.signal?.aborted) throw new AbortError();
      throw new ConnectionError(`${method} ${path} failed: ${String(cause)}`, cause);
    } finally {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", relay);
    }
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
    }
    if (response.status >= 200 && response.status < 300) {
      return (json ?? {}) as T;
    }
    const errorBody = json && typeof json === "object" ? (json as Record<string, unknown>) : {};
    const error = new MatrixError(response.status, errorBody, response.headers.get("Retry-After"));
    if (error.isUnknownToken && options.auth !== false && this.accessToken && !this.refreshAccessToken) {
      this.onUnknownToken?.(error);
    }
    throw error;
  }
}
