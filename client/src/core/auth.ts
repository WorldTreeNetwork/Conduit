// Password login, registration and User-Interactive Authentication.
// https://spec.matrix.org/v1.19/client-server-api/#user-interactive-authentication-api
import { MatrixError } from "./errors";
import type { HttpClient } from "./http";
import type { Session } from "./types";

export const DEVICE_DISPLAY_NAME = "Conduit web";

interface LoginResponse {
  user_id: string;
  access_token: string;
  device_id: string;
  well_known?: { "m.homeserver"?: { base_url?: string } };
}

export interface LoginFlow {
  type: string;
}

export async function getLoginFlows(http: HttpClient): Promise<LoginFlow[]> {
  const body = await http.request<{ flows?: LoginFlow[] }>("GET", "/_matrix/client/v3/login", { auth: false });
  return Array.isArray(body.flows) ? body.flows : [];
}

export async function loginWithPassword(
  http: HttpClient,
  user: string,
  password: string,
): Promise<Session> {
  const trimmed = user.trim();
  const identifier = { type: "m.id.user", user: trimmed };
  const body = await http.request<LoginResponse>("POST", "/_matrix/client/v3/login", {
    auth: false,
    maxRetries: 1,
    body: {
      type: "m.login.password",
      identifier,
      password,
      initial_device_display_name: DEVICE_DISPLAY_NAME,
    },
  });
  return toSession(http, body);
}

/** Stages this client can complete without further UI. */
export interface UiaCredentials {
  /** Needed for m.login.password stages (e.g. deleting a device). */
  password?: string;
  userId?: string;
}

export class UnsupportedAuthError extends Error {
  readonly flows: string[][];
  constructor(flows: string[][]) {
    super(
      `The server asks for sign-up steps this client does not support yet (${flows
        .map((f) => f.join(" → "))
        .join("; ")}).`,
    );
    this.name = "UnsupportedAuthError";
    this.flows = flows;
  }
}

interface UiaState {
  session?: string;
  flows: { stages: string[] }[];
  completed: string[];
}

function parseUia(error: unknown): UiaState | undefined {
  if (!(error instanceof MatrixError) || error.httpStatus !== 401) return undefined;
  const flows = error.body.flows;
  if (!Array.isArray(flows)) return undefined;
  return {
    session: typeof error.body.session === "string" ? error.body.session : undefined,
    flows: flows.filter(
      (f): f is { stages: string[] } => !!f && typeof f === "object" && Array.isArray((f as { stages?: unknown }).stages),
    ),
    completed: Array.isArray(error.body.completed) ? (error.body.completed as string[]) : [],
  };
}

function stageAuth(stage: string, session: string | undefined, creds: UiaCredentials): Record<string, unknown> | undefined {
  switch (stage) {
    case "m.login.dummy":
      return { type: stage, session };
    case "m.login.password":
      if (!creds.password || !creds.userId) return undefined;
      return {
        type: stage,
        session,
        identifier: { type: "m.id.user", user: creds.userId },
        password: creds.password,
      };
    default:
      return undefined;
  }
}

/**
 * Run `call` through UIA: first without `auth`, then completing each stage of
 * the first flow made only of stages we can satisfy.
 */
export async function withUia<T>(
  call: (auth: Record<string, unknown> | undefined) => Promise<T>,
  creds: UiaCredentials = {},
): Promise<T> {
  let auth: Record<string, unknown> | undefined = undefined;
  for (let round = 0; round < 8; round++) {
    try {
      return await call(auth);
    } catch (error) {
      const state = parseUia(error);
      if (!state) throw error;
      // A 401 carrying an errcode after we sent auth means the stage failed.
      if (auth && error instanceof MatrixError && error.body.errcode && state.completed.length === 0) {
        throw error;
      }
      const flow = state.flows.find((f) => f.stages.every((s) => stageAuth(s, state.session, creds)));
      if (!flow) throw new UnsupportedAuthError(state.flows.map((f) => f.stages));
      const next = flow.stages.find((s) => !state.completed.includes(s));
      if (!next) throw error;
      auth = stageAuth(next, state.session, creds);
    }
  }
  throw new Error("User-interactive authentication did not complete.");
}

export async function register(http: HttpClient, username: string, password: string): Promise<Session> {
  const body = await withUia((auth) =>
    http.request<LoginResponse>("POST", "/_matrix/client/v3/register", {
      auth: false,
      maxRetries: 1,
      query: { kind: "user" },
      body: {
        username: username.trim(),
        password,
        initial_device_display_name: DEVICE_DISPLAY_NAME,
        ...(auth ? { auth } : {}),
      },
    }),
  );
  return toSession(http, body);
}

export async function logout(http: HttpClient): Promise<void> {
  await http.request("POST", "/_matrix/client/v3/logout", { body: {}, maxRetries: 1 });
}

export async function whoami(http: HttpClient): Promise<{ user_id: string; device_id?: string }> {
  return http.request("GET", "/_matrix/client/v3/account/whoami");
}

function toSession(http: HttpClient, body: LoginResponse): Session {
  if (!body.user_id || !body.access_token) {
    throw new Error("The server did not return a usable session.");
  }
  const advertised = body.well_known?.["m.homeserver"]?.base_url;
  return {
    homeserverUrl: typeof advertised === "string" && /^https?:\/\//.test(advertised)
      ? advertised.replace(/\/+$/, "")
      : http.baseUrl,
    userId: body.user_id,
    accessToken: body.access_token,
    deviceId: body.device_id,
  };
}

/** Client-side username check (spec "user identifiers" grammar for localparts). */
export function validateUsername(username: string): string | undefined {
  const value = username.trim();
  if (!value) return "Choose a username.";
  if (!/^[a-z0-9._=\-/+]+$/.test(value)) {
    return "Use lowercase letters, digits, and . _ = - / + only.";
  }
  if (value.length > 200) return "That username is too long.";
  return undefined;
}
