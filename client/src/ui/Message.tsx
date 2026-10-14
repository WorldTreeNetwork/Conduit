import { createContext, Fragment, useContext, useState, type ReactNode } from "react";
import { MessageSquareReply, MessagesSquare, Pencil, RotateCw, SmilePlus, Trash2 } from "lucide-react";
import {
  displayContent,
  relatesTo,
  stripReplyFallback,
  type Aggregations,
  type MatrixEvent,
  type PendingEvent,
  type Room,
} from "../core";
import { useClient } from "./hooks";
import { formatTime, initialOf, messageView, tintIndex } from "./format";
import { CarrierMark, type CarrierState } from "./Mark";
import { FileMessage, ImageMessage } from "./Media";
import { isRelationSend } from "./timelineItems";

/** Actions the room view wires up for every message row. */
export interface TimelineActions {
  reply(eventId: string): void;
  edit(eventId: string): void;
  openThread(rootId: string): void;
  remove(eventId: string): void;
}

export const TimelineActionsContext = createContext<TimelineActions | null>(null);

const MEDIA_TYPES = new Set(["m.image", "m.file", "m.video", "m.audio"]);

function Readers({ room, readers }: { room: Room; readers?: string[] }) {
  if (!readers?.length) return null;
  const names = readers.map((id) => room.memberName(id));
  const label = `Seen by ${names.join(", ")}`;
  return (
    <p className="readers" data-testid="read-receipts" data-readers={readers.join(" ")} title={label}>
      <span className="visually-hidden">{label}</span>
      <span className="readers-plates" aria-hidden="true">
        {readers.slice(0, 5).map((id) => (
          <span key={id} className={`avatar avatar-xs tint-${tintIndex(id)}`}>
            {initialOf(room.memberName(id))}
          </span>
        ))}
        {readers.length > 5 && <span className="readers-more">+{readers.length - 5}</span>}
      </span>
    </p>
  );
}

export const QUICK_REACTIONS = ["👍", "❤️", "😂", "🎉", "😮", "🙏"];

const URL_RE = /(https?:\/\/[^\s<]+[^\s<.,;:!?)\]'"])/g;

export function linkify(text: string): ReactNode {
  const parts = text.split(URL_RE);
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <a key={i} href={part} target="_blank" rel="noopener noreferrer">
        {part}
      </a>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  );
}

export function MessageBody({ msgtype, body, sender, edited }: { msgtype: string; body: string; sender: string; edited?: boolean }) {
  const editedMark = edited ? (
    <span className="msg-edited" data-testid="edited-marker">
      {" "}
      (edited)
    </span>
  ) : null;
  if (msgtype === "m.emote") {
    return (
      <p className="msg-body msg-emote" data-testid="message-body">
        <span className="emote-sender">{sender}</span> {linkify(body)}
        {editedMark}
      </p>
    );
  }
  const muted = msgtype === "m.redacted" || msgtype === "m.bad.encrypted";
  return (
    <p className={`msg-body${msgtype === "m.notice" ? " msg-notice" : ""}${muted ? " msg-muted" : ""}`} data-testid="message-body">
      {linkify(body)}
      {editedMark}
    </p>
  );
}

/** The message's current text after edits, with any reply fallback removed. */
export function currentView(event: MatrixEvent, aggregations: Aggregations): { msgtype: string; body: string; edited: boolean } {
  const { content, edited } = displayContent(event, aggregations);
  const view = messageView({ ...event, content });
  const isReply = !!relatesTo(event).inReplyTo;
  return { msgtype: view.msgtype, body: isReply ? stripReplyFallback(view.body) : view.body, edited };
}

function focusEvent(eventId: string) {
  const el = document.querySelector<HTMLElement>(`[data-event-id="${CSS.escape(eventId)}"][data-timeline-item]`);
  if (!el) return;
  el.scrollIntoView({ block: "center" });
  el.tabIndex = 0;
  el.focus();
}

function ReplyQuote({ room, eventId, aggregations }: { room: Room; eventId: string; aggregations: Aggregations }) {
  const target = room.findEvent(eventId);
  if (!target) {
    return (
      <p className="reply-quote reply-missing" data-testid="reply-quote">
        In reply to an earlier message
      </p>
    );
  }
  const view = currentView(target, aggregations);
  return (
    <button type="button" className="reply-quote" onClick={() => focusEvent(eventId)} data-testid="reply-quote" data-reply-to={eventId}>
      <span className="reply-sender">{room.memberName(target.sender)}</span>
      <span className="reply-snippet">{view.body.split("\n")[0]}</span>
    </button>
  );
}

function Reactions({ room, event, aggregations }: { room: Room; event: MatrixEvent; aggregations: Aggregations }) {
  const client = useClient();
  const groups = aggregations.reactions.get(event.event_id);
  if (!groups?.length) return null;
  return (
    <ul className="reactions" aria-label="Reactions" data-testid="reactions">
      {groups.map((group) => {
        const mine = group.senders.includes(client.userId);
        const names = group.senders.map((s) => (s === client.userId ? "you" : room.memberName(s))).join(", ");
        return (
          <li key={group.key}>
            <button
              type="button"
              className={`reaction${mine ? " reaction-mine" : ""}`}
              aria-pressed={mine}
              aria-label={`${group.key} ${group.count}, from ${names}`}
              title={`Reacted by ${names}`}
              data-testid="reaction"
              data-key={group.key}
              data-count={group.count}
              onClick={() => {
                if (mine && group.ownEventId && !group.ownEventId.startsWith("~")) {
                  void client.redact(room.roomId, group.ownEventId).catch(() => undefined);
                } else if (!mine) {
                  client.react(room.roomId, event.event_id, group.key);
                }
              }}
            >
              <span aria-hidden="true">{group.key}</span>
              <span className="reaction-count" aria-hidden="true">
                {group.count}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function ReactionPicker({ room, event, onDone }: { room: Room; event: MatrixEvent; onDone: () => void }) {
  const client = useClient();
  const existing = new Set(
    (client.getRoom(room.roomId)?.aggregations(client.userId).reactions.get(event.event_id) ?? [])
      .filter((g) => g.senders.includes(client.userId))
      .map((g) => g.key),
  );
  return (
    <div
      className="reaction-picker"
      role="group"
      aria-label="Choose a reaction"
      data-testid="reaction-picker"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onDone();
        }
      }}
    >
      {QUICK_REACTIONS.map((key, i) => (
        <button
          key={key}
          type="button"
          className="icon-button reaction-option"
          aria-label={`React with ${key}`}
          disabled={existing.has(key)}
          autoFocus={i === 0}
          data-testid="reaction-option"
          data-key={key}
          onClick={() => {
            client.react(room.roomId, event.event_id, key);
            onDone();
          }}
        >
          {key}
        </button>
      ))}
    </div>
  );
}

function canRedactOthers(room: Room, userId: string): boolean {
  const pl = room.getStateContent("m.room.power_levels");
  const needed = typeof pl?.redact === "number" ? pl.redact : 50;
  return room.powerLevel(userId) >= needed;
}

function MessageActions({ room, event, inThread }: { room: Room; event: MatrixEvent; inThread: boolean }) {
  const client = useClient();
  const actions = useContext(TimelineActionsContext);
  const [picking, setPicking] = useState(false);
  if (!actions || event.unsigned?.redacted_because) return null;
  const mine = event.sender === client.userId;
  const textual = event.type === "m.room.message";
  return (
    <div className="msg-actions" role="toolbar" aria-label="Message actions" data-testid="message-actions">
      {picking ? (
        <ReactionPicker room={room} event={event} onDone={() => setPicking(false)} />
      ) : (
        <button type="button" className="icon-button" aria-label="React" title="React" onClick={() => setPicking(true)} data-testid="action-react">
          <SmilePlus size={16} aria-hidden="true" />
        </button>
      )}
      <button type="button" className="icon-button" aria-label="Reply" title="Reply" onClick={() => actions.reply(event.event_id)} data-testid="action-reply">
        <MessageSquareReply size={16} aria-hidden="true" />
      </button>
      {!inThread && (
        <button type="button" className="icon-button" aria-label="Reply in thread" title="Reply in thread" onClick={() => actions.openThread(event.event_id)} data-testid="action-thread">
          <MessagesSquare size={16} aria-hidden="true" />
        </button>
      )}
      {mine && textual && (
        <button type="button" className="icon-button" aria-label="Edit" title="Edit" onClick={() => actions.edit(event.event_id)} data-testid="action-edit">
          <Pencil size={16} aria-hidden="true" />
        </button>
      )}
      {(mine || canRedactOthers(room, client.userId)) && (
        <button type="button" className="icon-button" aria-label="Delete" title="Delete" onClick={() => actions.remove(event.event_id)} data-testid="action-delete">
          <Trash2 size={16} aria-hidden="true" />
        </button>
      )}
    </div>
  );
}

function ThreadSummary({ room, rootId, aggregations }: { room: Room; rootId: string; aggregations: Aggregations }) {
  const actions = useContext(TimelineActionsContext);
  const summary = aggregations.threads.get(rootId);
  if (!summary || summary.count === 0 || !actions) return null;
  const latest = summary.latest;
  return (
    <button type="button" className="thread-summary" onClick={() => actions.openThread(rootId)} data-testid="thread-summary" data-count={summary.count}>
      <MessagesSquare size={14} aria-hidden="true" />
      <span className="thread-count">
        {summary.count} {summary.count === 1 ? "reply" : "replies"}
      </span>
      {latest && <span className="thread-latest">Latest from {room.memberName(latest.sender)}</span>}
    </button>
  );
}

export function MessageRow({
  event,
  grouped,
  room,
  tabStop,
  aggregations,
  inThread = false,
  readers,
}: {
  event: MatrixEvent;
  grouped: boolean;
  room: Room;
  tabStop: boolean;
  aggregations: Aggregations;
  inThread?: boolean;
  readers?: string[];
}) {
  const client = useClient();
  const view = currentView(event, aggregations);
  const sender = room.memberName(event.sender);
  const mine = event.sender === client.userId;
  const time = formatTime(event.origin_server_ts);
  const rel = relatesTo(event);
  return (
    <li
      className={`msg${grouped ? " msg-grouped" : ""}${mine ? " msg-mine" : ""}`}
      data-timeline-item
      tabIndex={tabStop ? 0 : -1}
      data-testid="timeline-item"
      data-kind="message"
      data-event-id={event.event_id}
      data-sender={event.sender}
      data-msgtype={view.msgtype}
      aria-label={`${sender}, ${time}: ${view.msgtype === "m.emote" ? `${sender} ` : ""}${view.body}${view.edited ? " (edited)" : ""}`}
    >
      {!grouped ? (
        <span className={`avatar tint-${tintIndex(event.sender)}`} aria-hidden="true">
          {initialOf(sender)}
        </span>
      ) : (
        <span className="msg-gutter" aria-hidden="true">
          <time className="stamp stamp-hover" dateTime={new Date(event.origin_server_ts).toISOString()}>
            {time}
          </time>
        </span>
      )}
      <div className="msg-main">
        {!grouped && (
          <p className="msg-head">
            <span className="msg-sender" data-testid="message-sender">
              {sender}
            </span>
            <time className="stamp" dateTime={new Date(event.origin_server_ts).toISOString()}>
              {time}
            </time>
          </p>
        )}
        {rel.inReplyTo && !(inThread && rel.isFallingBack) && (
          <ReplyQuote room={room} eventId={rel.inReplyTo} aggregations={aggregations} />
        )}
        <div className="msg-line">
          {MEDIA_TYPES.has(view.msgtype) ? (
            view.msgtype === "m.image" ? (
              <ImageMessage content={displayContent(event, aggregations).content} />
            ) : (
              <FileMessage content={displayContent(event, aggregations).content} />
            )
          ) : (
            <MessageBody msgtype={view.msgtype} body={view.body} sender={sender} edited={view.edited} />
          )}
          {mine && <CarrierMark state="delivered" />}
        </div>
        <Reactions room={room} event={event} aggregations={aggregations} />
        <Readers room={room} readers={readers} />
        {!inThread && <ThreadSummary room={room} rootId={event.event_id} aggregations={aggregations} />}
      </div>
      <MessageActions room={room} event={event} inThread={inThread} />
    </li>
  );
}

function relationLabel(p: PendingEvent): string {
  if (p.type === "m.reaction") {
    const key = (p.content["m.relates_to"] as { key?: string } | undefined)?.key ?? "";
    return `Reaction ${key}`;
  }
  return "Edit";
}

export function PendingRow({ pending, grouped, room, tabStop }: { pending: PendingEvent; grouped: boolean; room: Room; tabStop: boolean }) {
  const client = useClient();
  const sender = room.memberName(client.userId);
  const relation = isRelationSend(pending);
  const newContent = pending.content["m.new_content"] as { body?: string } | undefined;
  const body = relation ? `${relationLabel(pending)}: ${String(newContent?.body ?? "")}`.replace(/: $/, "") : String(pending.content.body ?? "");
  const msgtype = String(pending.content.msgtype ?? "m.text");
  const state: CarrierState = pending.status;
  const failed = pending.status === "failed";
  const replyTo = relatesTo(pending).inReplyTo;
  return (
    <li
      className={`msg msg-mine msg-pending${grouped ? " msg-grouped" : ""}${failed ? " msg-failed" : ""}`}
      data-timeline-item
      tabIndex={tabStop ? 0 : -1}
      data-testid="pending-item"
      data-kind="pending"
      data-status={pending.status}
      data-txn-id={pending.txnId}
      aria-label={`${sender}: ${body}. ${failed ? "Not sent" : pending.status === "sent" ? "Sent" : "Sending"}`}
    >
      {!grouped ? (
        <span className={`avatar tint-${tintIndex(client.userId)}`} aria-hidden="true">
          {initialOf(sender)}
        </span>
      ) : (
        <span className="msg-gutter" aria-hidden="true" />
      )}
      <div className="msg-main">
        {!grouped && (
          <p className="msg-head">
            <span className="msg-sender">{sender}</span>
            <span className="stamp">{failed ? "Not sent" : "Sending…"}</span>
          </p>
        )}
        {replyTo && <ReplyQuote room={room} eventId={replyTo} aggregations={room.aggregations(client.userId)} />}
        <div className="msg-line">
          {pending.attachment && msgtype === "m.image" && pending.attachment.localUrl ? (
            <ImageMessage content={pending.content} localUrl={pending.attachment.localUrl} />
          ) : pending.attachment ? (
            <FileMessage content={{ ...pending.content, url: undefined }} />
          ) : (
            <MessageBody msgtype={relation ? "m.notice" : msgtype} body={body} sender={sender} />
          )}
          <CarrierMark state={state} />
        </div>
        {failed && (
          <div className="send-failure" role="alert" data-testid="send-failure">
            <span>
              {relation ? `${relationLabel(pending)} not saved.` : "Not sent."} {pending.error}
            </span>
            <button type="button" className="link-button link-signal" onClick={() => client.retrySend(pending.txnId)} data-testid="retry-send">
              <RotateCw size={14} aria-hidden="true" /> Retry
            </button>
            <button type="button" className="link-button link-signal" onClick={() => client.discardSend(pending.txnId)} data-testid="discard-send">
              <Trash2 size={14} aria-hidden="true" /> Delete
            </button>
          </div>
        )}
      </div>
    </li>
  );
}
