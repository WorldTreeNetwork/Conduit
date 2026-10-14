import { useEffect, useRef, useState } from "react";
import { LogIn, Plus, Settings as SettingsIcon } from "lucide-react";
import { useClient, useClientVersion, useHashRoute, type Route } from "./hooks";
import { RoomList } from "./RoomList";
import { RoomView } from "./RoomView";
import { Settings } from "./Settings";
import { ConnectionBanner, LineStatus } from "./ConnectionBanner";
import { CreateRoomDialog, JoinRoomDialog } from "./Dialogs";
import { Mark } from "./Mark";
import { initialOf } from "./format";
import { ReauthScreen } from "./Account";

type DialogName = "create" | "join" | null;

export function Shell({ onSignOut, onDeactivated }: { onSignOut: () => Promise<void>; onDeactivated: () => void }) {
  const client = useClient();
  useClientVersion();
  const [route, navigate] = useHashRoute();
  const [dialog, setDialog] = useState<DialogName>(null);
  const [profileName, setProfileName] = useState<string | undefined>(undefined);
  const mainRef = useRef<HTMLElement>(null);

  // A route that points at a room we are no longer in falls back home.
  const roomGone = route.name === "room" && client.syncHealth.ready && !client.getRoom(route.roomId);
  useEffect(() => {
    if (roomGone) navigate({ name: "home" });
  }, [roomGone, navigate]);

  // Profile is fetched once; local edits win over a slower in-flight fetch.
  const profileEdited = useRef(false);
  useEffect(() => {
    let cancelled = false;
    client
      .getProfile(client.userId)
      .then((p) => !cancelled && !profileEdited.current && setProfileName(p.displayname || undefined))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [client]);
  const onProfileChanged = (name: string) => {
    profileEdited.current = true;
    setProfileName(name || undefined);
  };

  const open = (next: Route) => navigate(next);
  const displayName = profileName ?? client.userId;

  if (client.softLoggedOut) return <ReauthScreen onSignOut={onSignOut} />;

  return (
    <div className="shell" data-view={route.name === "room" && !client.getRoom(route.roomId) ? "home" : route.name}>
      <a className="skip-link" href="#main">
        Skip to conversation
      </a>
      <aside className="board" aria-label="Rooms and account">
        <header className="board-head">
          <Mark size={24} />
          <span className="board-wordmark">Conduit</span>
        </header>
        <div className="board-actions">
          <button type="button" className="button button-board" onClick={() => setDialog("create")} data-testid="open-create-room">
            <Plus size={16} aria-hidden="true" /> New room
          </button>
          <button type="button" className="button button-board" onClick={() => setDialog("join")} data-testid="open-join-room">
            <LogIn size={16} aria-hidden="true" /> Join
          </button>
        </div>
        <RoomList
          selectedRoomId={route.name === "room" ? route.roomId : undefined}
          onOpen={(roomId) => open({ name: "room", roomId })}
          onCreate={() => setDialog("create")}
        />
        <footer className="board-foot">
          <LineStatus />
          <a
            className={`account${route.name === "settings" ? " account-current" : ""}`}
            href="#/settings"
            aria-current={route.name === "settings" ? "page" : undefined}
            data-testid="open-settings"
          >
            <span className="avatar avatar-sm" aria-hidden="true">
              {initialOf(displayName)}
            </span>
            <span className="account-text">
              <span className="account-name" data-testid="account-name">
                {displayName}
              </span>
              <span className="account-id">{client.userId}</span>
            </span>
            <SettingsIcon size={18} aria-hidden="true" />
            <span className="visually-hidden">Settings</span>
          </a>
        </footer>
      </aside>
      <main id="main" className="main" ref={mainRef} tabIndex={-1}>
        <ConnectionBanner />
        {route.name === "room" && client.getRoom(route.roomId) ? (
          <RoomView key={route.roomId} roomId={route.roomId} onLeft={() => open({ name: "home" })} />
        ) : route.name === "settings" ? (
          <Settings onSignOut={onSignOut} onDeactivated={onDeactivated} onProfileChanged={onProfileChanged} />
        ) : (
          <Welcome onCreate={() => setDialog("create")} onJoin={() => setDialog("join")} />
        )}
      </main>
      <CreateRoomDialog
        open={dialog === "create"}
        onClose={() => setDialog(null)}
        onCreated={(roomId) => {
          setDialog(null);
          open({ name: "room", roomId });
        }}
      />
      <JoinRoomDialog
        open={dialog === "join"}
        onClose={() => setDialog(null)}
        onJoined={(roomId) => {
          setDialog(null);
          open({ name: "room", roomId });
        }}
      />
    </div>
  );
}

function Welcome({ onCreate, onJoin }: { onCreate: () => void; onJoin: () => void }) {
  const client = useClient();
  useClientVersion();
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.focus();
    document.title = "Conduit";
  }, []);
  const ready = client.syncHealth.ready;
  const count = client.roomList().length;
  return (
    <section className="welcome" aria-labelledby="welcome-heading" data-testid="welcome">
      <h1 id="welcome-heading" ref={headingRef} tabIndex={-1} className="plate-title">
        {!ready ? "Connecting to your server…" : count === 0 ? "No rooms yet" : "Pick a room"}
      </h1>
      {ready && (
        <p className="welcome-copy">
          {count === 0
            ? "Rooms are where conversations happen. Start one and invite people, or join one you already know the address of."
            : "Choose a room from the board on the left, or start something new."}
        </p>
      )}
      {ready && (
        <div className="welcome-actions">
          <button type="button" className="button button-primary" onClick={onCreate} data-testid="welcome-create">
            Create a room
          </button>
          <button type="button" className="button button-quiet" onClick={onJoin} data-testid="welcome-join">
            Join by address
          </button>
        </div>
      )}
    </section>
  );
}
