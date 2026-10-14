import { useLayoutEffect, useState, type KeyboardEvent, type RefObject } from "react";
import { SendHorizontal } from "lucide-react";
import type { Room } from "../core";
import { useClient } from "./hooks";

/** "/me waves" sends an emote; "//text" escapes a leading slash. */
export function parseComposer(text: string): { body: string; msgtype: "m.text" | "m.emote" } | undefined {
  const trimmed = text.replace(/\s+$/, "");
  if (!trimmed.trim()) return undefined;
  if (/^\/me\s/.test(trimmed)) return { body: trimmed.slice(4), msgtype: "m.emote" };
  if (trimmed.startsWith("//")) return { body: trimmed.slice(1), msgtype: "m.text" };
  return { body: trimmed, msgtype: "m.text" };
}

export function Composer({ room, inputRef }: { room: Room; inputRef: RefObject<HTMLTextAreaElement> }) {
  const client = useClient();
  const [text, setText] = useState("");
  const name = room.displayName(client.userId);
  const blocked = room.isEncrypted && !client.crypto.enabled;

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
    client.sendMessage(room.roomId, parsed.body, parsed.msgtype);
    setText("");
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      send();
    }
  }

  return (
    <form
      className="composer"
      onSubmit={(e) => {
        e.preventDefault();
        send();
      }}
      data-testid="composer"
    >
      <label htmlFor="composer-input" className="visually-hidden">
        Message {name}
      </label>
      <textarea
        id="composer-input"
        ref={inputRef}
        className="composer-input"
        rows={1}
        value={text}
        placeholder={blocked ? "This room is encrypted; sending is not supported yet" : `Message ${name}`}
        disabled={blocked}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={onKeyDown}
        aria-describedby="composer-hint"
        data-testid="composer-input"
      />
      <p id="composer-hint" className="visually-hidden">
        Enter sends. Shift and Enter adds a new line. Start with /me to describe an action.
      </p>
      <button
        type="submit"
        className="button button-primary composer-send"
        disabled={blocked || !parseComposer(text)}
        data-testid="composer-send"
      >
        <SendHorizontal size={18} aria-hidden="true" />
        <span>Send</span>
      </button>
    </form>
  );
}
