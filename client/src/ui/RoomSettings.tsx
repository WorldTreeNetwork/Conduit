import { useEffect, useRef, useState, type FormEvent } from "react";
import { describeError, type JsonObject, type Room } from "../core";
import { Dialog } from "./Dialogs";
import { Field } from "./Field";
import { useClient, useClientVersion } from "./hooks";
import { initialOf, tintIndex } from "./format";

function requiredLevel(room: Room, type: string): number {
  const pl = room.getStateContent("m.room.power_levels") ?? {};
  const events = (pl.events ?? {}) as Record<string, unknown>;
  if (typeof events[type] === "number") return events[type] as number;
  return typeof pl.state_default === "number" ? pl.state_default : 50;
}

const ROLES = [
  { level: 0, label: "Member" },
  { level: 50, label: "Moderator" },
  { level: 100, label: "Admin" },
];

const VISIBILITY = [
  { value: "shared", label: "Members, including history from before they joined" },
  { value: "invited", label: "Members, from the time they were invited" },
  { value: "joined", label: "Members, from the time they joined" },
  { value: "world_readable", label: "Anyone, even without joining" },
];

/** Room name, topic, avatar, who can join, history visibility and roles. */
export function RoomSettingsDialog({ open, room, onClose }: { open: boolean; room: Room; onClose: () => void }) {
  const client = useClient();
  useClientVersion();
  const me = room.powerLevel(client.userId);
  const can = (type: string) => me >= requiredLevel(room, type);
  const [name, setName] = useState("");
  const [topic, setTopic] = useState("");
  const [joinRule, setJoinRule] = useState("invite");
  const [visibility, setVisibility] = useState("shared");
  const [status, setStatus] = useState<{ ok?: string; error?: string }>({});
  const [pending, setPending] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setName(room.explicitName ?? "");
    setTopic(room.topic ?? "");
    setJoinRule(room.joinRule ?? "invite");
    setVisibility(String(room.getStateContent("m.room.history_visibility")?.history_visibility ?? "shared"));
    setStatus({});
  }, [open, room]);

  async function save(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setStatus({});
    try {
      const changes: [string, JsonObject][] = [];
      if (name.trim() !== (room.explicitName ?? "") && can("m.room.name")) changes.push(["m.room.name", { name: name.trim() }]);
      if (topic.trim() !== (room.topic ?? "") && can("m.room.topic")) changes.push(["m.room.topic", { topic: topic.trim() }]);
      if (joinRule !== (room.joinRule ?? "invite") && can("m.room.join_rules")) changes.push(["m.room.join_rules", { join_rule: joinRule }]);
      const currentVisibility = String(room.getStateContent("m.room.history_visibility")?.history_visibility ?? "shared");
      if (visibility !== currentVisibility && can("m.room.history_visibility")) {
        changes.push(["m.room.history_visibility", { history_visibility: visibility }]);
      }
      for (const [type, content] of changes) await client.setRoomState(room.roomId, type, content);
      setStatus({ ok: changes.length ? "Saved." : "Nothing to change." });
    } catch (e) {
      setStatus({ error: describeError(e) });
    } finally {
      setPending(false);
    }
  }

  async function changeAvatar(files: FileList | null) {
    const file = files?.[0];
    if (!file) return;
    setStatus({});
    try {
      const url = await client.uploadFile(file, file.name);
      await client.setRoomState(room.roomId, "m.room.avatar", { url, info: { mimetype: file.type, size: file.size } });
      setStatus({ ok: "Room picture updated." });
    } catch (e) {
      setStatus({ error: describeError(e) });
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  const members = room
    .members()
    .filter((m) => m.membership === "join")
    .sort((a, b) => room.powerLevel(b.userId) - room.powerLevel(a.userId) || a.userId.localeCompare(b.userId));
  const canRoles = can("m.room.power_levels");
  const readOnly = !can("m.room.name") && !can("m.room.topic") && !can("m.room.join_rules");

  return (
    <Dialog open={open} onClose={onClose} title="Room settings" testId="room-settings-dialog" wide>
      {readOnly && (
        <p className="callout callout-info" data-testid="room-settings-readonly">
          Only moderators and admins can change these settings.
        </p>
      )}
      <form onSubmit={save} noValidate className="room-settings">
        <Field id="rs-name" label="Name" value={name} onChange={setName} testId="room-settings-name" />
        <Field id="rs-topic" label="Topic" value={topic} onChange={setTopic} multiline testId="room-settings-topic" />
        <div className="field">
          <label className="field-label" htmlFor="rs-join">
            Who can join
          </label>
          <select id="rs-join" className="input" value={joinRule} onChange={(e) => setJoinRule(e.target.value)} disabled={!can("m.room.join_rules")} data-testid="room-settings-join-rule">
            <option value="invite">Only people who are invited</option>
            <option value="public">Anyone who knows the address</option>
            <option value="knock">Anyone can ask to join</option>
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="rs-history">
            Who can read history
          </label>
          <select id="rs-history" className="input" value={visibility} onChange={(e) => setVisibility(e.target.value)} disabled={!can("m.room.history_visibility")} data-testid="room-settings-history">
            {VISIBILITY.map((v) => (
              <option key={v.value} value={v.value}>
                {v.label}
              </option>
            ))}
          </select>
        </div>
        <div className="settings-row">
          <button type="submit" className="button button-primary" disabled={pending || readOnly} aria-busy={pending} data-testid="room-settings-save">
            {pending ? "Saving…" : "Save changes"}
          </button>
          <input ref={fileRef} type="file" accept="image/*" className="visually-hidden" tabIndex={-1} aria-hidden="true" onChange={(e) => void changeAvatar(e.target.files)} data-testid="room-avatar-input" />
          <button type="button" className="button button-quiet" disabled={!can("m.room.avatar")} onClick={() => fileRef.current?.click()} data-testid="room-avatar-button">
            Change picture
          </button>
        </div>
        <p role="status" className={status.error ? "field-error" : "muted"} data-testid="room-settings-status">
          {status.error ?? status.ok ?? ""}
        </p>
      </form>
      <section className="roles" aria-labelledby="roles-heading">
        <h3 id="roles-heading" className="panel-label">
          Roles
        </h3>
        <ul className="member-list" data-testid="role-list">
          {members.map((m) => {
            const level = room.powerLevel(m.userId);
            const editable = canRoles && m.userId !== client.userId && level < me;
            const label = room.memberName(m.userId);
            return (
              <li key={m.userId} className="member" data-testid="role-row" data-user-id={m.userId}>
                <span className={`avatar avatar-sm tint-${tintIndex(m.userId)}`} aria-hidden="true">
                  {initialOf(label)}
                </span>
                <span className="member-text">
                  <span className="member-name">{label}</span>
                </span>
                <select
                  className="input input-compact"
                  aria-label={`Role for ${label}`}
                  value={ROLES.some((r) => r.level === level) ? level : ""}
                  disabled={!editable}
                  data-testid="role-select"
                  onChange={async (e) => {
                    setStatus({});
                    try {
                      await client.setPowerLevel(room.roomId, m.userId, Number(e.target.value));
                      setStatus({ ok: `${label} is now ${ROLES.find((r) => r.level === Number(e.target.value))?.label}.` });
                    } catch (err) {
                      setStatus({ error: describeError(err) });
                    }
                  }}
                >
                  {!ROLES.some((r) => r.level === level) && <option value="">Custom ({level})</option>}
                  {ROLES.filter((r) => r.level <= me || r.level === level).map((r) => (
                    <option key={r.level} value={r.level}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </li>
            );
          })}
        </ul>
      </section>
    </Dialog>
  );
}
