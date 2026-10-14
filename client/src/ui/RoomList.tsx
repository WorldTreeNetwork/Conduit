import { useState, type KeyboardEvent } from "react";
import { describeError, type RoomListEntry } from "../core";
import { useClient, useClientVersion } from "./hooks";
import { formatPreviewTime, initialOf, tintIndex } from "./format";
import { CarrierMark } from "./Mark";

interface Props {
  selectedRoomId?: string;
  onOpen: (roomId: string) => void;
  onCreate: () => void;
}

/** Arrow keys move between rooms; Home/End jump; Tab leaves the list. */
function onListKeyDown(event: KeyboardEvent<HTMLElement>) {
  const keys = ["ArrowDown", "ArrowUp", "Home", "End"];
  if (!keys.includes(event.key)) return;
  const items = [...event.currentTarget.querySelectorAll<HTMLElement>("[data-room-nav]")];
  if (items.length === 0) return;
  const index = items.indexOf(document.activeElement as HTMLElement);
  let next = index;
  if (event.key === "ArrowDown") next = index < 0 ? 0 : Math.min(items.length - 1, index + 1);
  if (event.key === "ArrowUp") next = index < 0 ? 0 : Math.max(0, index - 1);
  if (event.key === "Home") next = 0;
  if (event.key === "End") next = items.length - 1;
  event.preventDefault();
  for (const item of items) item.tabIndex = -1;
  const target = items[next]!;
  target.tabIndex = 0;
  target.focus();
}

export function RoomList({ selectedRoomId, onOpen, onCreate }: Props) {
  const client = useClient();
  useClientVersion();
  const ready = client.syncHealth.ready;
  const entries = client.roomList();
  const invites = entries.filter((e) => e.membership === "invite");
  const rooms = entries.filter((e) => e.membership === "join");
  // Roving tabindex: the selected room (or the first) is the list's tab stop.
  const tabStop = rooms.find((r) => r.roomId === selectedRoomId)?.roomId ?? rooms[0]?.roomId;

  if (!ready) {
    return (
      <nav className="room-nav" aria-label="Rooms" aria-busy="true" data-testid="room-list-loading">
        <p className="visually-hidden">Loading your rooms…</p>
        <ul className="room-list" aria-hidden="true">
          {[0, 1, 2, 3].map((i) => (
            <li key={i} className="room-row room-row-skeleton">
              <span className="avatar skeleton" />
              <span className="skeleton-lines">
                <span className="skeleton skeleton-line" />
                <span className="skeleton skeleton-line skeleton-short" />
              </span>
            </li>
          ))}
        </ul>
      </nav>
    );
  }

  return (
    <nav className="room-nav" aria-label="Rooms" onKeyDown={onListKeyDown} data-testid="room-list">
      {invites.length > 0 && (
        <section aria-labelledby="invites-label" className="room-section">
          <h2 id="invites-label" className="board-label">
            Invites <span className="board-count">{invites.length}</span>
          </h2>
          <ul className="room-list">
            {invites.map((entry) => (
              <InviteRow key={entry.roomId} entry={entry} onAccepted={onOpen} />
            ))}
          </ul>
        </section>
      )}
      <section aria-labelledby="rooms-label" className="room-section">
        <h2 id="rooms-label" className="board-label">
          Rooms
        </h2>
        {rooms.length === 0 ? (
          <div className="board-empty" data-testid="room-list-empty">
            <p>No rooms yet.</p>
            <button type="button" className="link-button link-on-board" onClick={onCreate}>
              Create your first room
            </button>
          </div>
        ) : (
          <ul className="room-list">
            {rooms.map((entry) => (
              <RoomRow
                key={entry.roomId}
                entry={entry}
                selected={entry.roomId === selectedRoomId}
                tabStop={entry.roomId === tabStop}
                onOpen={onOpen}
              />
            ))}
          </ul>
        )}
      </section>
    </nav>
  );
}

function RoomRow({
  entry,
  selected,
  tabStop,
  onOpen,
}: {
  entry: RoomListEntry;
  selected: boolean;
  tabStop: boolean;
  onOpen: (roomId: string) => void;
}) {
  const client = useClient();
  const room = client.getRoom(entry.roomId);
  const senderName = entry.preview
    ? entry.preview.sender === client.userId
      ? "You"
      : room?.memberName(entry.preview.sender) ?? entry.preview.sender
    : undefined;
  const unread = entry.unread > 0 && !selected;
  const status = entry.preview?.status;
  const jammed = entry.failedSends > 0;
  const label = [
    entry.name,
    unread ? `${entry.unread} unread${entry.highlights ? `, ${entry.highlights} mentioning you` : ""}` : undefined,
    jammed ? `${entry.failedSends} not sent` : undefined,
  ]
    .filter(Boolean)
    .join(", ");
  return (
    <li>
      <a
        href={`#/room/${encodeURIComponent(entry.roomId)}`}
        className={`room-row${selected ? " room-row-selected" : ""}${unread ? " room-row-unread" : ""}`}
        aria-current={selected ? "page" : undefined}
        aria-label={label}
        tabIndex={tabStop ? 0 : -1}
        data-room-nav
        data-testid="room-row"
        data-room-id={entry.roomId}
        data-room-name={entry.name}
        onClick={(e) => {
          e.preventDefault();
          onOpen(entry.roomId);
        }}
      >
        <span className={`avatar tint-${tintIndex(entry.roomId)}`} aria-hidden="true">
          {initialOf(entry.name)}
        </span>
        <span className="room-row-body" aria-hidden="true">
          <span className="room-row-top">
            <span className="room-name">{entry.name}</span>
            <span className="room-time">{formatPreviewTime(entry.preview?.ts ?? 0)}</span>
          </span>
          <span className="room-row-bottom">
            {status && status !== "sent" && <CarrierMark state={status} />}
            <span className="room-preview" data-testid="room-preview">
              {jammed && status === "failed" ? (
                <>
                  <span className="room-preview-jam" data-testid="room-jam">
                    Not sent:
                  </span>{" "}
                  {entry.preview?.body}
                </>
              ) : entry.preview ? (
                `${senderName}: ${entry.preview.body}`
              ) : (
                entry.topic ?? "No messages yet"
              )}
            </span>
            {selected && !unread && <span className="active-lamp" data-testid="active-lamp" />}
            {unread && (
              <span
                className={`lamp${entry.highlights ? " lamp-highlight" : ""}`}
                data-testid="unread-badge"
                data-count={entry.unread}
              >
                {entry.unread > 99 ? "99+" : entry.unread}
              </span>
            )}
          </span>
        </span>
      </a>
    </li>
  );
}

function InviteRow({ entry, onAccepted }: { entry: RoomListEntry; onAccepted: (roomId: string) => void }) {
  const client = useClient();
  const [pending, setPending] = useState<"accept" | "decline" | null>(null);
  const [error, setError] = useState<string | undefined>(undefined);
  const inviter = entry.inviter;
  const room = client.getRoom(entry.roomId);
  const inviterName = inviter
    ? (room?.inviteState.find((e) => e.type === "m.room.member" && e.state_key === inviter)?.content.displayname as
        | string
        | undefined) ?? inviter
    : undefined;

  async function act(kind: "accept" | "decline") {
    setPending(kind);
    setError(undefined);
    try {
      if (kind === "accept") {
        const roomId = await client.acceptInvite(entry.roomId);
        onAccepted(roomId);
      } else {
        await client.rejectInvite(entry.roomId);
      }
    } catch (e) {
      setError(describeError(e));
    } finally {
      setPending(null);
    }
  }

  return (
    <li className="invite-row" data-testid="invite-row" data-room-id={entry.roomId} data-room-name={entry.name}>
      <span className={`avatar tint-${tintIndex(entry.roomId)}`} aria-hidden="true">
        {initialOf(entry.name)}
      </span>
      <div className="invite-body">
        <span className="room-name">{entry.name}</span>
        {inviterName && <span className="room-preview">Invited by {inviterName}</span>}
        <div className="invite-actions">
          <button
            type="button"
            className="button button-primary button-small"
            onClick={() => act("accept")}
            disabled={pending !== null}
            aria-busy={pending === "accept"}
            aria-label={`Accept invite to ${entry.name}`}
            data-testid="accept-invite"
          >
            {pending === "accept" ? "Joining…" : "Accept"}
          </button>
          <button
            type="button"
            className="button button-board button-small"
            onClick={() => act("decline")}
            disabled={pending !== null}
            aria-busy={pending === "decline"}
            aria-label={`Decline invite to ${entry.name}`}
            data-testid="decline-invite"
          >
            {pending === "decline" ? "Declining…" : "Decline"}
          </button>
        </div>
        {error && (
          <p className="board-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </li>
  );
}
