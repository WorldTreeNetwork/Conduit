import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type RefObject } from "react";
import { Paperclip, Pencil, Reply, SendHorizontal, X } from "lucide-react";
import { imageSize } from "./Media";
import type { Room } from "../core";
import { useClient } from "./hooks";
import { currentView } from "./Message";

/** "/me waves" sends an emote; "//text" escapes a leading slash. */
export function parseComposer(text: string): { body: string; msgtype: "m.text" | "m.emote" } | undefined {
  const trimmed = text.replace(/\s+$/, "");
  if (!trimmed.trim()) return undefined;
  if (/^\/me\s/.test(trimmed)) return { body: trimmed.slice(4), msgtype: "m.emote" };
  if (trimmed.startsWith("//")) return { body: trimmed.slice(1), msgtype: "m.text" };
  return { body: trimmed, msgtype: "m.text" };
}

export type ComposerContext = { kind: "reply"; eventId: string } | { kind: "edit"; eventId: string };

interface ComposerProps {
  room: Room;
  inputRef: RefObject<HTMLTextAreaElement>;
  /** Unique per composer on the page (main vs thread). */
  id: string;
  label: string;
  context: ComposerContext | null;
  onClearContext: () => void;
  /** Post into this thread instead of the main timeline. */
  threadRootId?: string;
  /** ArrowUp in an empty composer edits the last own message. */
  onRequestEditLast?: () => void;
}

export function Composer({ room, inputRef, id, label, context, onClearContext, threadRootId, onRequestEditLast }: ComposerProps) {
  const client = useClient();
  const [text, setText] = useState("");
  const blocked = room.isEncrypted && !client.crypto.enabled;
  const target = context ? room.findEvent(context.eventId) : undefined;
  const fileRef = useRef<HTMLInputElement>(null);
  const idleTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Typing notifications: on while there is text, off after 5s idle, on
  // send, or when leaving the room.
  const stopTyping = () => {
    if (idleTimer.current) clearTimeout(idleTimer.current);
    idleTimer.current = undefined;
    client.setTyping(room.roomId, false);
  };
  useEffect(
    () => () => {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      client.setTyping(room.roomId, false);
    },
    [client, room.roomId],
  );
  function onTextChange(value: string) {
    setText(value);
    if (!value.trim() || context?.kind === "edit") {
      stopTyping();
      return;
    }
    client.setTyping(room.roomId, true);
    if (idleTimer.current) clearTimeout(idleTimer.current);
    idleTimer.current = setTimeout(() => client.setTyping(room.roomId, false), 5_000);
  }

  async function attach(files: FileList | null) {
    for (const file of Array.from(files ?? [])) {
      const size = await imageSize(file);
      client.sendAttachment(room.roomId, file, size);
    }
    if (fileRef.current) fileRef.current.value = "";
  }
  const aggregations = room.aggregations(client.userId);

  // Entering edit mode loads the current text; leaving it clears.
  const editId = context?.kind === "edit" ? context.eventId : undefined;
  useEffect(() => {
    if (!editId) return;
    const event = room.findEvent(editId);
    if (!event) return;
    const view = currentView(event, room.aggregations(client.userId));
    setText(view.msgtype === "m.emote" ? `/me ${view.body}` : view.body);
    inputRef.current?.focus();
  }, [editId, room, client.userId, inputRef]);

  useEffect(() => {
    if (context?.kind === "reply") inputRef.current?.focus();
  }, [context, inputRef]);

  // Grow with the text up to the CSS max-height.
  useLayoutEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [text, inputRef]);

  function send() {
    const parsed = parseComposer(text);
    if (!parsed || blocked) return;
    if (context?.kind === "edit") {
      const event = room.findEvent(context.eventId);
      const before = event ? currentView(event, aggregations) : undefined;
      if (!before || before.body !== parsed.body || before.msgtype !== parsed.msgtype) {
        client.editMessage(room.roomId, context.eventId, parsed.body, parsed.msgtype);
      }
    } else if (context?.kind === "reply") {
      client.sendReply(room.roomId, context.eventId, parsed.body, parsed.msgtype);
    } else if (threadRootId) {
      client.sendThreadMessage(room.roomId, threadRootId, parsed.body, parsed.msgtype);
    } else {
      client.sendMessage(room.roomId, parsed.body, parsed.msgtype);
    }
    setText("");
    stopTyping();
    if (context) onClearContext();
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      send();
    } else if (event.key === "Escape" && context) {
      event.preventDefault();
      if (context.kind === "edit") setText("");
      onClearContext();
    } else if (event.key === "ArrowUp" && !text && !context && onRequestEditLast) {
      event.preventDefault();
      onRequestEditLast();
    }
  }

  const hintId = `${id}-hint`;
  return (
    <form
      className={`composer${context ? " composer-with-context" : ""}`}
      onSubmit={(e) => {
        e.preventDefault();
        send();
      }}
      data-testid={threadRootId ? "thread-composer" : "composer"}
    >
      {context && (
        <div className="composer-context" data-testid="composer-context" data-kind={context.kind}>
          {context.kind === "edit" ? <Pencil size={14} aria-hidden="true" /> : <Reply size={14} aria-hidden="true" />}
          <span className="composer-context-text">
            {context.kind === "edit" ? "Editing your message" : `Replying to ${target ? room.memberName(target.sender) : "a message"}`}
            {target && context.kind === "reply" && (
              <span className="composer-context-snippet"> · {currentView(target, aggregations).body.split("\n")[0]}</span>
            )}
          </span>
          <button
            type="button"
            className="icon-button"
            aria-label={context.kind === "edit" ? "Cancel editing" : "Cancel reply"}
            onClick={() => {
              if (context.kind === "edit") setText("");
              onClearContext();
              inputRef.current?.focus();
            }}
            data-testid="cancel-context"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
      )}
      <div className="composer-row">
        {!threadRootId && (
          <>
            <input
              ref={fileRef}
              type="file"
              multiple
              className="visually-hidden"
              tabIndex={-1}
              aria-hidden="true"
              onChange={(e) => void attach(e.target.files)}
              data-testid="attach-input"
            />
            <button
              type="button"
              className="icon-button composer-attach"
              aria-label="Attach files"
              title="Attach files"
              disabled={blocked}
              onClick={() => fileRef.current?.click()}
              data-testid="attach-button"
            >
              <Paperclip size={18} aria-hidden="true" />
            </button>
          </>
        )}
        <label htmlFor={id} className="visually-hidden">
          {label}
        </label>
        <textarea
          id={id}
          ref={inputRef}
          className="composer-input"
          rows={1}
          value={text}
          placeholder={blocked ? "This room is encrypted; sending is not supported yet" : label}
          disabled={blocked}
          onChange={(e) => onTextChange(e.target.value)}
          onKeyDown={onKeyDown}
          aria-describedby={hintId}
          data-testid={threadRootId ? "thread-composer-input" : "composer-input"}
        />
        <p id={hintId} className="visually-hidden">
          Enter sends. Shift and Enter adds a new line. Start with /me to describe an action.
          {onRequestEditLast ? " Up arrow in an empty box edits your last message." : ""}
          {context ? " Escape cancels." : ""}
        </p>
        <button
          type="submit"
          className="button button-primary composer-send"
          disabled={blocked || !parseComposer(text)}
          data-testid={threadRootId ? "thread-composer-send" : "composer-send"}
        >
          <SendHorizontal size={18} aria-hidden="true" />
          <span>{context?.kind === "edit" ? "Save" : "Send"}</span>
        </button>
      </div>
    </form>
  );
}
