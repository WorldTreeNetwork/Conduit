// Error taxonomy for the HTTP layer.
//
// MatrixError: the server answered with a Matrix error body
//   ({"errcode": "...", "error": "..."}), or at least a non-2xx status.
// ConnectionError: no HTTP answer at all (DNS, refused, reset, aborted by
//   timeout). These are always transient from the client's point of view.

export class MatrixError extends Error {
  readonly errcode: string;
  readonly httpStatus: number;
  readonly retryAfterMs: number | undefined;
  readonly body: Record<string, unknown>;

  constructor(httpStatus: number, body: Record<string, unknown>, retryAfterHeader?: string | null) {
    const errcode = typeof body.errcode === "string" ? body.errcode : `M_HTTP_${httpStatus}`;
    const message = typeof body.error === "string" ? body.error : `HTTP ${httpStatus}`;
    super(message);
    this.name = "MatrixError";
    this.errcode = errcode;
    this.httpStatus = httpStatus;
    this.body = body;
    this.retryAfterMs = parseRetryAfter(body, retryAfterHeader);
  }

  /** M_UNKNOWN_TOKEN: the access token is no longer valid. */
  get isUnknownToken(): boolean {
    return this.errcode === "M_UNKNOWN_TOKEN";
  }

  get isSoftLogout(): boolean {
    return this.isUnknownToken && this.body.soft_logout === true;
  }

  get isRateLimited(): boolean {
    return this.httpStatus === 429 || this.errcode === "M_LIMIT_EXCEEDED";
  }

  /** Worth retrying the identical request later. */
  get isTransient(): boolean {
    return this.isRateLimited || this.httpStatus >= 500 || this.httpStatus === 408;
  }
}

export class ConnectionError extends Error {
  readonly cause: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "ConnectionError";
    this.cause = cause;
  }
}

export class AbortError extends Error {
  constructor() {
    super("aborted");
    this.name = "AbortError";
  }
}

export function isTransient(error: unknown): boolean {
  if (error instanceof ConnectionError) return true;
  if (error instanceof MatrixError) return error.isTransient;
  return false;
}

function parseRetryAfter(body: Record<string, unknown>, header?: string | null): number | undefined {
  // v1.10+: the Retry-After header is authoritative; retry_after_ms is the
  // deprecated body field still sent by most servers.
  if (header) {
    const seconds = Number(header);
    if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  }
  const ms = body.retry_after_ms;
  return typeof ms === "number" && ms >= 0 ? ms : undefined;
}

/** A short human sentence for an error, suitable for inline UI. */
export function describeError(error: unknown): string {
  if (error instanceof MatrixError) {
    switch (error.errcode) {
      case "M_FORBIDDEN":
        return error.message && error.message !== "HTTP 403" ? error.message : "You are not allowed to do that.";
      case "M_USER_IN_USE":
        return "That username is taken. Try another.";
      case "M_INVALID_USERNAME":
        return "Usernames may only contain a-z, 0-9, and . _ = - /";
      case "M_WEAK_PASSWORD":
        return "That password is too weak.";
      case "M_UNKNOWN_TOKEN":
        return "Your session has ended. Sign in again.";
      case "M_LIMIT_EXCEEDED":
        return "The server is busy. Wait a moment and try again.";
      case "M_NOT_FOUND":
        return error.message || "Not found.";
      case "M_ROOM_IN_USE":
        return "That room alias is already in use.";
      default:
        return error.message || `Request failed (${error.errcode}).`;
    }
  }
  if (error instanceof ConnectionError) return "Can't reach the server. Check the address and your connection.";
  if (error instanceof Error) return error.message;
  return String(error);
}
