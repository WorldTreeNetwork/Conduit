import { X } from "lucide-react";
import type { MemberInfo, Room } from "../core";
import { useClient, useClientVersion } from "./hooks";
import { initialOf, tintIndex } from "./format";
import { PresenceLamp } from "./Presence";

function role(level: number): string | undefined {
  if (level >= 100) return "Admin";
  if (level >= 50) return "Moderator";
  return undefined;
}

export function MemberPanel({ room, onClose }: { room: Room; onClose: () => void }) {
  const client = useClient();
  useClientVersion();
  const members = room.members();
  const byName = (a: MemberInfo, b: MemberInfo) =>
    room.powerLevel(b.userId) - room.powerLevel(a.userId) ||
    room.memberName(a.userId).localeCompare(room.memberName(b.userId));
  const joined = members.filter((m) => m.membership === "join").sort(byName);
  const invited = members.filter((m) => m.membership === "invite").sort(byName);

  return (
    <aside id="member-panel" className="panel" aria-labelledby="members-heading" data-testid="member-panel">
      <header className="panel-head">
        <h2 id="members-heading" className="plate-subtitle">
          People
        </h2>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Close people panel" data-testid="close-members">
          <X size={18} aria-hidden="true" />
        </button>
      </header>
      <div className="panel-body">
        <h3 className="panel-label">
          In the room <span className="count">{joined.length}</span>
        </h3>
        <ul className="member-list" data-testid="joined-members">
          {joined.map((m) => (
            <MemberRow key={m.userId} member={m} room={room} self={m.userId === client.userId} />
          ))}
        </ul>
        {invited.length > 0 && (
          <>
            <h3 className="panel-label">
              Invited <span className="count">{invited.length}</span>
            </h3>
            <ul className="member-list" data-testid="invited-members">
              {invited.map((m) => (
                <MemberRow key={m.userId} member={m} room={room} self={m.userId === client.userId} />
              ))}
            </ul>
          </>
        )}
      </div>
    </aside>
  );
}

function MemberRow({ member, room, self }: { member: MemberInfo; room: Room; self: boolean }) {
  const name = room.memberName(member.userId);
  const badge = role(room.powerLevel(member.userId));
  return (
    <li className="member" data-testid="member-row" data-user-id={member.userId} data-membership={member.membership}>
      <span className={`avatar avatar-sm tint-${tintIndex(member.userId)}`} aria-hidden="true">
        {initialOf(name)}
      </span>
      <span className="member-text">
        <span className="member-name">
          {name}
          {self && <span className="member-you"> (you)</span>}
        </span>
        {name !== member.userId && <span className="member-id">{member.userId}</span>}
        {member.membership === "join" && <PresenceLamp userId={member.userId} />}
      </span>
      {badge && <span className="badge">{badge}</span>}
    </li>
  );
}
