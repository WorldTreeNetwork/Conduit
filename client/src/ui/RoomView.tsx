import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, DoorOpen, Settings2, UserPlus, Users } from "lucide-react";
import { relatesTo } from "../core";
import { useClient, useClientVersion } from "./hooks";
import { Timeline } from "./Timeline";
import { Composer, type ComposerContext } from "./Composer";
import { MemberPanel } from "./MemberPanel";
import { ThreadPanel } from "./ThreadPanel";
import { DeleteMessageDialog, InviteDialog, LeaveDialog } from "./Dialogs";
import { RoomSettingsDialog } from "./RoomSettings";
import { TimelineActionsContext, type TimelineActions } from "./Message";
import { TypingIndicator } from "./Presence";

type Panel = { kind: "members" } | { kind: "thread"; rootId: string } | null;

export function RoomView({ roomId, onLeft }: { roomId: string; onLeft: () => void }) {
  const client = useClient();
  useClientVersion();
  const room = client.getRoom(roomId);
  const [panel, setPanel] = useState<Panel>(() =>
    window.matchMedia?.("(min-width: 1180px)").matches ? { kind: "members" } : null,
  );
  const [dialog, setDialog] = useState<"invite" | "leave" | "settings" | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [context, setContext] = useState<ComposerContext | null>(null);
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

  const actions = useMemo<TimelineActions>(
    () => ({
      reply: (eventId) => setContext({ kind: "reply", eventId }),
      edit: (eventId) => setContext({ kind: "edit", eventId }),
      openThread: (rootId) => setPanel({ kind: "thread", rootId }),
      remove: (eventId) => setDeleteTarget(eventId),
    }),
    [],
  );

  const editLast = useCallback(() => {
    if (!room) return;
    const agg = room.aggregations(client.userId);
    for (let i = room.timeline.length - 1; i >= 0; i--) {
      const event = room.timeline[i]!;
      if (event.sender !== client.userId || event.type !== "m.room.message") continue;
      if (agg.hidden.has(event.event_id) || event.unsigned?.redacted_because || relatesTo(event).relType) continue;
      setContext({ kind: "edit", eventId: event.event_id });
      return;
    }
  }, [room, client.userId]);

  if (!room) return null;
  const joinedCount = room.members().filter((m) => m.membership === "join").length;
  const membersOpen = panel?.kind === "members";

  return (
    <TimelineActionsContext.Provider value={actions}>
      <div className={`room${panel ? " room-with-panel" : ""}`} data-testid="room-view" data-room-id={roomId}>
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
              <button type="button" className="button button-quiet button-small" onClick={(event) => { event.currentTarget.focus(); setDialog("invite"); }} data-testid="open-invite">
                <UserPlus size={16} aria-hidden="true" /> <span className="label">Invite</span>
              </button>
              <button
                type="button"
                className="button button-quiet button-small"
                aria-pressed={membersOpen}
                aria-controls={membersOpen ? "member-panel" : undefined}
                onClick={() => setPanel(membersOpen ? null : { kind: "members" })}
                data-testid="toggle-members"
              >
                <Users size={16} aria-hidden="true" /> <span className="label">People</span> <span className="count">{joinedCount}</span>
              </button>
              <button
                type="button"
                className="button button-quiet button-small"
                onClick={(event) => { event.currentTarget.focus(); setDialog("settings"); }}
                aria-label="Room settings"
                data-testid="open-room-settings"
              >
                <Settings2 size={16} aria-hidden="true" />
              </button>
              <button type="button" className="button button-quiet button-small" onClick={(event) => { event.currentTarget.focus(); setDialog("leave"); }} data-testid="open-leave">
                <DoorOpen size={16} aria-hidden="true" /> <span className="label">Leave</span>
              </button>
            </div>
          </header>
          <Timeline room={room} />
          <TypingIndicator room={room} />
          <Composer
            room={room}
            inputRef={composerRef}
            id="composer-input"
            label={`Message ${name}`}
            context={context}
            onClearContext={() => setContext(null)}
            onRequestEditLast={editLast}
          />
        </section>
        {panel?.kind === "members" && <MemberPanel room={room} onClose={() => setPanel(null)} />}
        {panel?.kind === "thread" && (
          <ThreadPanel key={panel.rootId} room={room} rootId={panel.rootId} onClose={() => setPanel(null)} />
        )}
        <InviteDialog open={dialog === "invite"} roomId={roomId} roomName={name} onClose={() => setDialog(null)} />
        <RoomSettingsDialog open={dialog === "settings"} room={room} onClose={() => setDialog(null)} />
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
        <DeleteMessageDialog
          open={deleteTarget !== null}
          roomId={roomId}
          eventId={deleteTarget}
          onClose={() => setDeleteTarget(null)}
        />
      </div>
    </TimelineActionsContext.Provider>
  );
}
