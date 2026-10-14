// Homeserver discovery: https://spec.matrix.org/v1.19/client-server-api/#server-discovery
//
// Input is whatever the person typed: a full URL ("http://127.0.0.1:8008"),
// a bare server name ("example.org"), or a Matrix ID ("@me:example.org").
import type { Clock } from "./clock";
import { ConnectionError, MatrixError } from "./errors";
import { HttpClient, type Transport } from "./http";

export type DiscoveryResult =
  | { kind: "ok"; baseUrl: string; versions: string[] }
  /** FAIL_PROMPT: well-known was present but unusable; ask the user. */
  | { kind: "prompt"; reason: string }
  /** FAIL_ERROR: the advertised homeserver does not answer as one. */
  | { kind: "error"; reason: string };

export function serverNameFromUserId(userId: string): string | undefined {
  const match = /^@[^:]+:(.+)$/.exec(userId.trim());
  return match?.[1];
}

function looksLikeUrl(input: string): boolean {
  return /^https?:\/\//i.test(input.trim());
}

export async function discoverHomeserver(
  input: string,
  options: { transport?: Transport; clock: Clock },
): Promise<DiscoveryResult> {
  const raw = input.trim();
  if (!raw) return { kind: "prompt", reason: "Enter a homeserver address." };
  if (looksLikeUrl(raw)) {
    return validateHomeserver(raw, options);
  }
  const serverName = serverNameFromUserId(raw) ?? raw;
  const wellKnown = new HttpClient({ baseUrl: `https://${serverName}`, ...options });
  let baseUrl: string | undefined;
  try {
    const body = await wellKnown.request<Record<string, unknown>>("GET", "/.well-known/matrix/client", {
      auth: false,
      maxRetries: 0,
      timeoutMs: 10_000,
    });
    const homeserver = body["m.homeserver"];
    if (!homeserver || typeof homeserver !== "object") {
      return { kind: "prompt", reason: "The server's .well-known file has no m.homeserver entry." };
    }
    const advertised = (homeserver as Record<string, unknown>).base_url;
    if (typeof advertised !== "string" || !looksLikeUrl(advertised)) {
      return { kind: "prompt", reason: "The server's .well-known base_url is not a valid URL." };
    }
    baseUrl = advertised;
  } catch (error) {
    if (error instanceof MatrixError && error.httpStatus === 404) {
      // IGNORE: no well-known; fall back to the server name itself.
      baseUrl = `https://${serverName}`;
    } else if (error instanceof ConnectionError) {
      baseUrl = `https://${serverName}`;
    } else {
      return { kind: "prompt", reason: "The server's .well-known file could not be read." };
    }
  }
  return validateHomeserver(baseUrl, options);
}

export async function validateHomeserver(
  baseUrl: string,
  options: { transport?: Transport; clock: Clock },
): Promise<DiscoveryResult> {
  const http = new HttpClient({ baseUrl, ...options });
  try {
    const body = await http.request<{ versions?: unknown }>("GET", "/_matrix/client/versions", {
      auth: false,
      maxRetries: 1,
      timeoutMs: 10_000,
    });
    const versions = Array.isArray(body.versions)
      ? body.versions.filter((v): v is string => typeof v === "string")
      : [];
    if (versions.length === 0) {
      return { kind: "error", reason: "That address does not answer as a Matrix homeserver." };
    }
    return { kind: "ok", baseUrl: http.baseUrl, versions };
  } catch {
    return { kind: "error", reason: `Can't reach a Matrix homeserver at ${baseUrl}.` };
  }
}
