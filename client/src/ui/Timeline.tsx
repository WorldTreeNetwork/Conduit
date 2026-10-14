import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { ArrowDown, ChevronRight } from "lucide-react";
import { describeError, type Aggregations, type Room } from "../core";
import { useClient, useClientVersion } from "./hooks";
import { eventKind, formatDay, formatTime } from "./format";
import { buildItems, pendingRelationEvents, type Item } from "./timelineItems";
import { MessageRow, PendingRow, currentView } from "./Message";

const NEAR_BOTTOM_PX = 80;

export function Timeline({ room }: { room: Room }) {
  const client = useClient();
  const version = useClientVersion();
  const scrollRef = useRef<HTMLDivElement>(null);
  const topRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);
  const [atBottom, setAtBottom] = useState(true);
  const [paging, setPaging] = useState(false);
  const [pageError, setPageError] = useState<string | undefined>(undefined);
  const [announcement, setAnnouncement] = useState("");
  const anchorRef = useRef<{ height: number; top: number } | null>(null);
  const lastAnnounced = useRef<string | undefined>(room.lastEvent?.event_id);

  const pending = client.sendQueue.forRoom(room.roomId);
  const aggregations = room.aggregations(client.userId, pendingRelationEvents(pending, client.userId));
  const items = buildItems(room, pending, client.userId, aggregations);
  const readers = client.readersByEvent(room.roomId);
  const exhausted = room.historyExhausted;

  const paginate = useCallback(async () => {
    if (paging || room.historyExhausted) return;
    const el = scrollRef.current;
    if (el) anchorRef.current = { height: el.scrollHeight, top: el.scrollTop };
    setPaging(true);
    setPageError(undefined);
    try {
      await client.paginateBack(room.roomId);
    } catch (error) {
      anchorRef.current = null;
      setPageError(describeError(error));
    } finally {
      setPaging(false);
    }
  }, [client, room, paging]);

  // Keep the reader's place: after prepending history, restore the offset;
  // when they were at the bottom, follow new messages.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (anchorRef.current) {
      const { height, top } = anchorRef.current;
      if (el.scrollHeight !== height) {
        el.scrollTop = top + (el.scrollHeight - height);
        anchorRef.current = null;
      }
    } else if (atBottomRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [version]);

  // Auto-load older history when the top sentinel is visible (also fills a
  // short timeline).
  useEffect(() => {
    const sentinel = topRef.current;
    const root = scrollRef.current;
    if (!sentinel || !root || exhausted || pageError) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) void paginate();
      },
      { root, rootMargin: "200px 0px 0px 0px" },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [paginate, exhausted, pageError]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const bottom = el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_BOTTOM_PX;
    atBottomRef.current = bottom;
    if (bottom !== atBottom) setAtBottom(bottom);
  };

  // Read receipts while the latest message is on screen.
  const lastId = room.lastEvent?.event_id;
  useEffect(() => {
    if (atBottom && document.visibilityState === "visible") void client.markRead(room.roomId);
  }, [client, room.roomId, lastId, atBottom]);

  // Announce new messages from other people to screen readers.
  useEffect(() => {
    const last = room.lastEvent;
    if (!last || last.event_id === lastAnnounced.current) return;
    lastAnnounced.current = last.event_id;
    if (last.sender === client.userId || eventKind(last) !== "message") return;
    const agg = room.aggregations(client.userId);
    if (agg.hidden.has(last.event_id)) return;
    setAnnouncement(`${room.memberName(last.sender)}: ${currentView(last, agg).body}`);
  }, [client.userId, room, lastId]);

  const jumpToLatest = () => {
    const el = scrollRef.current;
    if (!el) return;
    atBottomRef.current = true;
    setAtBottom(true);
    el.scrollTop = el.scrollHeight;
    const items = el.querySelectorAll<HTMLElement>("[data-timeline-item]");
    const last = items[items.length - 1];
    if (last) focusItem(el, last);
  };

  const roomName = room.displayName(client.userId);
  const lastItemKey = [...items].reverse().find((i) => i.kind !== "day")?.key;

  return (
    <div className="timeline-wrap">
      <div
        className="timeline-scroll"
        ref={scrollRef}
        onScroll={onScroll}
        data-testid="timeline"
        aria-busy={paging}
      >
        <div ref={topRef} className="timeline-top">
          {exhausted ? (
            <p className="timeline-start" data-testid="timeline-start">
              This is the beginning of {roomName}.
            </p>
          ) : pageError ? (
            <p className="timeline-status" role="alert" data-testid="pagination-error">
              Couldn't load older messages. {pageError}{" "}
              <button type="button" className="link-button" onClick={() => void paginate()} data-testid="retry-pagination">
                Try again
              </button>
            </p>
          ) : (
            <button
              type="button"
              className="button button-quiet button-small"
              onClick={() => void paginate()}
              disabled={paging}
              data-testid="load-older"
            >
              {paging ? "Loading older messages…" : "Load older messages"}
            </button>
          )}
        </div>
        {items.length === 0 && exhausted && (
          <p className="timeline-empty" data-testid="timeline-empty">
            No messages yet. Say hello.
          </p>
        )}
        <ol className="timeline" aria-label={`Messages in ${roomName}`} onKeyDown={onTimelineKeyDown}>
          {items.map((item) => (
            <TimelineRow
              key={item.key}
              item={item}
              room={room}
              tabStop={item.key === lastItemKey}
              aggregations={aggregations}
              readers={item.kind === "message" ? readers.get(item.event.event_id) : undefined}
            />
          ))}
        </ol>
      </div>
      {!atBottom && (
        <button type="button" className="jump-latest button button-primary button-small" onClick={jumpToLatest} data-testid="jump-to-latest">
          <ArrowDown size={16} aria-hidden="true" /> Jump to latest
        </button>
      )}
      <div className="visually-hidden" aria-live="polite" data-testid="message-announcer">
        {announcement}
      </div>
    </div>
  );
}

function focusItem(scroller: HTMLElement, item: HTMLElement) {
  for (const other of scroller.querySelectorAll<HTMLElement>("[data-timeline-item]")) other.tabIndex = -1;
  item.tabIndex = 0;
  item.focus();
}

function onTimelineKeyDown(event: KeyboardEvent<HTMLOListElement>) {
  if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
  const target = event.target as HTMLElement;
  if (!target.matches("[data-timeline-item]")) return;
  const items = [...event.currentTarget.querySelectorAll<HTMLElement>("[data-timeline-item]")];
  const index = items.indexOf(target);
  let next = index;
  if (event.key === "ArrowUp") next = Math.max(0, index - 1);
  if (event.key === "ArrowDown") next = Math.min(items.length - 1, index + 1);
  if (event.key === "Home") next = 0;
  if (event.key === "End") next = items.length - 1;
  event.preventDefault();
  focusItem(event.currentTarget, items[next]!);
}

function TimelineRow({
  item,
  room,
  tabStop,
  aggregations,
  readers,
}: {
  item: Item;
  room: Room;
  tabStop: boolean;
  aggregations: Aggregations;
  readers?: string[];
}) {
  switch (item.kind) {
    case "day":
      return (
        <li className="day-plate" data-testid="day-separator">
          <span>{formatDay(item.ts)}</span>
        </li>
      );
    case "state":
      return (
        <li
          className="state-line"
          data-timeline-item
          tabIndex={tabStop ? 0 : -1}
          data-testid="state-line"
          data-event-id={item.event.event_id}
          data-event-type={item.event.type}
        >
          <span className="state-text">{item.text}</span>
          <time className="stamp" dateTime={new Date(item.event.origin_server_ts).toISOString()}>
            {formatTime(item.event.origin_server_ts)}
          </time>
        </li>
      );
    case "creation":
      return (
        <li className="state-line state-group" data-timeline-item tabIndex={tabStop ? 0 : -1} data-testid="creation-summary">
          <details>
            <summary>
              <ChevronRight size={14} aria-hidden="true" className="state-chevron" />
              <span className="state-text">
                {room.memberName(item.sender)} created and configured the room
                <span className="state-count"> · {item.lines.length} changes</span>
              </span>
              <time className="stamp" dateTime={new Date(item.lines[0]!.event.origin_server_ts).toISOString()}>
                {formatTime(item.lines[0]!.event.origin_server_ts)}
              </time>
            </summary>
            <ul className="state-group-list">
              {item.lines.map(({ event, text }) => (
                <li key={event.event_id} data-testid="state-line" data-event-id={event.event_id} data-event-type={event.type}>
                  {text}
                </li>
              ))}
            </ul>
          </details>
        </li>
      );
    case "message":
      return (
        <MessageRow event={item.event} grouped={item.grouped} room={room} tabStop={tabStop} aggregations={aggregations} readers={readers} />
      );
    case "pending":
      return <PendingRow pending={item.pending} grouped={item.grouped} room={room} tabStop={tabStop} />;
  }
}
