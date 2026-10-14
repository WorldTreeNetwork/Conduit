import type { Room } from "../core";
import { useClient, useClientVersion } from "./hooks";

/** "Sam is typing…" under the timeline, from m.typing ephemeral events. */
export function TypingIndicator({ room }: { room: Room }) {
  const client = useClient();
  useClientVersion();
  const others = room.typing.filter((id) => id !== client.userId);
  let text = "";
  if (others.length === 1) text = `${room.memberName(others[0]!)} is typing…`;
  else if (others.length === 2) text = `${room.memberName(others[0]!)} and ${room.memberName(others[1]!)} are typing…`;
  else if (others.length > 2) text = "Several people are typing…";
  return (
    <p className="typing" data-testid="typing-indicator" data-count={others.length} aria-hidden={others.length === 0}>
      {others.length > 0 && (
        <>
          <span className="typing-dots" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          {text}
        </>
      )}
    </p>
  );
}

export type PresenceState = "online" | "unavailable" | "offline" | "unknown";

export function usePresence(userId: string): PresenceState {
  const client = useClient();
  useClientVersion();
  const entry = client.presence.get(userId);
  if (!entry) return "unknown";
  if (entry.presence === "online" || entry.presence === "unavailable" || entry.presence === "offline") return entry.presence;
  return "unknown";
}

const PRESENCE_LABEL: Record<PresenceState, string> = {
  online: "Online",
  unavailable: "Away",
  offline: "Offline",
  unknown: "",
};

/** A small lamp on a member's plate; the state is also given as text. */
export function PresenceLamp({ userId }: { userId: string }) {
  const state = usePresence(userId);
  if (state === "unknown") return null;
  return (
    <span className={`presence presence-${state}`} data-testid="presence" data-presence={state}>
      <span className="presence-lamp" aria-hidden="true" />
      <span className="presence-label">{PRESENCE_LABEL[state]}</span>
    </span>
  );
}
