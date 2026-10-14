import { useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { X } from "lucide-react";
import { describeError, type Room } from "../core";
import { Composer, type ComposerContext } from "./Composer";
import { useClient, useClientVersion } from "./hooks";
import { MessageRow, PendingRow, TimelineActionsContext, type TimelineActions } from "./Message";
import { isThreadSend, pendingRelationEvents } from "./timelineItems";
import { relatesTo } from "../core";

/** A thread beside the main timeline: root, replies and a thread composer. */
export function ThreadPanel({ room, rootId, onClose }: { room: Room; rootId: string; onClose: () => void }) {
  const client = useClient();
  useClientVersion();
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | undefined>(undefined);
  const [context, setContext] = useState<ComposerContext | null>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const parentActions = useContext(TimelineActionsContext);
  // Replies and edits inside the thread use the thread's own composer.
  const actions = useMemo<TimelineActions>(
    () => ({
      reply: (eventId) => setContext({ kind: "reply", eventId }),
      edit: (eventId) => setContext({ kind: "edit", eventId }),
      openThread: () => undefined,
      remove: (eventId) => parentActions?.remove(eventId),
    }),
    [parentActions],
  );
  const headingRef = useRef<HTMLHeadingElement>(null);

  const load = useCallback(() => {
    setStatus("loading");
    setError(undefined);
    client
      .loadThread(room.roomId, rootId)
      .then(() => setStatus("ready"))
      .catch((e) => {
        setError(describeError(e));
        setStatus("error");
      });
  }, [client, room.roomId, rootId]);

  useEffect(load, [load]);
  useEffect(() => {
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [rootId]);

  const root = room.findEvent(rootId);
  const pending = client.sendQueue
    .forRoom(room.roomId)
    .filter((p) => isThreadSend(p) && relatesTo(p).eventId === rootId && !(p.eventId && room.findEvent(p.eventId)));
  const aggregations = room.aggregations(client.userId, pendingRelationEvents(client.sendQueue.forRoom(room.roomId), client.userId));
  const replies = room.threadReplies(rootId, client.userId);

  return (
    <aside className="panel thread-panel" aria-labelledby="thread-heading" data-testid="thread-panel" data-root-id={rootId}>
      <header className="panel-head">
        <h2 id="thread-heading" className="plate-subtitle" ref={headingRef} tabIndex={-1}>
          Thread
        </h2>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Close thread" data-testid="close-thread">
          <X size={18} aria-hidden="true" />
        </button>
      </header>
      <div className="panel-body thread-body">
        <TimelineActionsContext.Provider value={actions}>
        <ol className="timeline thread-timeline" aria-label="Thread messages">
          {root && <MessageRow event={root} grouped={false} room={room} tabStop={false} aggregations={aggregations} inThread />}
          {status === "loading" && replies.length === 0 && (
            <li className="timeline-status" role="status" data-testid="thread-loading">
              Loading replies…
            </li>
          )}
          {status === "error" && (
            <li className="timeline-status" role="alert" data-testid="thread-error">
              Couldn't load this thread. {error}{" "}
              <button type="button" className="link-button" onClick={load}>
                Try again
              </button>
            </li>
          )}
          {status === "ready" && replies.length === 0 && pending.length === 0 && (
            <li className="timeline-status" data-testid="thread-empty">
              No replies yet. Start the thread below.
            </li>
          )}
          {replies.map((event, i) => (
            <MessageRow
              key={event.event_id}
              event={event}
              grouped={i > 0 && replies[i - 1]!.sender === event.sender}
              room={room}
              tabStop={i === replies.length - 1}
              aggregations={aggregations}
              inThread
            />
          ))}
          {pending.map((p) => (
            <PendingRow key={p.txnId} pending={p} grouped={false} room={room} tabStop={false} />
          ))}
        </ol>
        </TimelineActionsContext.Provider>
      </div>
      <Composer
        room={room}
        inputRef={inputRef}
        id="thread-composer-input"
        label="Reply in thread"
        context={context}
        onClearContext={() => setContext(null)}
        threadRootId={rootId}
      />
    </aside>
  );
}
