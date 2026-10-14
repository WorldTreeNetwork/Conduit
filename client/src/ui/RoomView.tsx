import { useEffect, useRef, useState } from "react";
import { ArrowLeft, DoorOpen, UserPlus, Users } from "lucide-react";
import { useClient, useClientVersion } from "./hooks";
import { Timeline } from "./Timeline";
import { Composer } from "./Composer";
import { MemberPanel } from "./MemberPanel";
import { InviteDialog, LeaveDialog } from "./Dialogs";

export function RoomView({ roomId, onLeft }: { roomId: string; onLeft: () => void }) {
  const client = useClient();
  useClientVersion();
  const room = client.getRoom(roomId);
  const [membersOpen, setMembersOpen] = useState(() => window.matchMedia?.("(min-width: 1180px)").matches ?? false);
  const [dialog, setDialog] = useState<"invite" | "leave" | null>(null);
  const composerRef = useRef<HTMLTextAreaElement>(null);
  const name = room?.displayName(client.userId) ?? roomId;

  useEffect(() => {
    document.title = `${name} · Conduit`;
  }, [name]);

  // Opening a room puts the cursor in the composer: the next likely action.
  // A frame later so a closing dialog's focus restoration doesn't win.
  useEffect(() => {
    const frame = requestAnimationFrame(() => composerRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [roomId]);

  if (!room) return null;
  const joinedCount = room.members().filter((m) => m.membership === "join").length;

  return (
    <div className={`room${membersOpen ? " room-with-panel" : ""}`} data-testid="room-view" data-room-id={roomId}>
      <section className="room-main" aria-labelledby="room-heading">
        <header className="room-head">
          <a href="#/" className="back-link icon-button" aria-label="All rooms">
            <ArrowLeft size={20} aria-hidden="true" />
          </a>
          <div className="room-head-text">
            <h1 id="room-heading" className="plate-title" tabIndex={-1} data-testid="room-heading">
              {name}
            </h1>
            {room.topic && (
              <p className="room-topic" data-testid="room-topic">
                {room.topic}
              </p>
            )}
          </div>
          <div className="room-head-actions" role="toolbar" aria-label="Room actions">
            <button type="button" className="button button-quiet button-small" onClick={() => setDialog("invite")} data-testid="open-invite">
              <UserPlus size={16} aria-hidden="true" /> <span className="label">Invite</span>
            </button>
            <button
              type="button"
              className="button button-quiet button-small"
              aria-pressed={membersOpen}
              aria-controls="member-panel"
              onClick={() => setMembersOpen((v) => !v)}
              data-testid="toggle-members"
            >
              <Users size={16} aria-hidden="true" /> <span className="label">People</span> <span className="count">{joinedCount}</span>
            </button>
            <button type="button" className="button button-quiet button-small" onClick={() => setDialog("leave")} data-testid="open-leave">
              <DoorOpen size={16} aria-hidden="true" /> <span className="label">Leave</span>
            </button>
          </div>
        </header>
        <Timeline room={room} />
        <Composer room={room} inputRef={composerRef} />
      </section>
      {membersOpen && <MemberPanel room={room} onClose={() => setMembersOpen(false)} />}
      <InviteDialog open={dialog === "invite"} roomId={roomId} roomName={name} onClose={() => setDialog(null)} />
      <LeaveDialog
        open={dialog === "leave"}
        roomId={roomId}
        roomName={name}
        onClose={() => setDialog(null)}
        onLeft={() => {
          setDialog(null);
          onLeft();
        }}
      />
    </div>
  );
}
