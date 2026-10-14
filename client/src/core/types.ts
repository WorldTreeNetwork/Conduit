// Wire types for the subset of the Matrix Client-Server API (v1.19) the core
// speaks. Shapes follow https://spec.matrix.org/v1.19/client-server-api/.
// Content is deliberately `Record<string, unknown>`: events are untrusted
// input and every reader narrows the fields it needs.

export type JsonObject = Record<string, unknown>;

/** A client-format event as delivered by /sync and /messages. */
export interface MatrixEvent {
  event_id: string;
  type: string;
  sender: string;
  origin_server_ts: number;
  content: JsonObject;
  room_id?: string;
  state_key?: string;
  unsigned?: {
    age?: number;
    transaction_id?: string;
    prev_content?: JsonObject;
    redacted_because?: JsonObject;
    [key: string]: unknown;
  };
}

/** Stripped state, as found in invite_state / knock_state. */
export interface StrippedStateEvent {
  type: string;
  state_key: string;
  sender: string;
  content: JsonObject;
}

export interface BasicEvent {
  type: string;
  content: JsonObject;
}

export interface Timeline {
  events?: MatrixEvent[];
  limited?: boolean;
  prev_batch?: string;
}

export interface RoomSummary {
  "m.heroes"?: string[];
  "m.joined_member_count"?: number;
  "m.invited_member_count"?: number;
}

export interface JoinedRoomSync {
  summary?: RoomSummary;
  state?: { events?: MatrixEvent[] };
  timeline?: Timeline;
  ephemeral?: { events?: BasicEvent[] };
  account_data?: { events?: BasicEvent[] };
  unread_notifications?: { highlight_count?: number; notification_count?: number };
}

export interface InvitedRoomSync {
  invite_state?: { events?: StrippedStateEvent[] };
}

export interface LeftRoomSync {
  state?: { events?: MatrixEvent[] };
  timeline?: Timeline;
  account_data?: { events?: BasicEvent[] };
}

export interface SyncResponse {
  next_batch: string;
  rooms?: {
    join?: Record<string, JoinedRoomSync>;
    invite?: Record<string, InvitedRoomSync>;
    leave?: Record<string, LeftRoomSync>;
    knock?: Record<string, unknown>;
  };
  account_data?: { events?: BasicEvent[] };
  presence?: { events?: BasicEvent[] };
  to_device?: { events?: JsonObject[] };
  device_lists?: { changed?: string[]; left?: string[] };
  device_one_time_keys_count?: Record<string, number>;
  device_unused_fallback_key_types?: string[];
}

export interface MessagesResponse {
  chunk: MatrixEvent[];
  start: string;
  end?: string;
  state?: MatrixEvent[];
}

export interface Session {
  homeserverUrl: string;
  userId: string;
  accessToken: string;
  deviceId: string;
}

export type Membership = "join" | "invite" | "leave" | "ban" | "knock";
