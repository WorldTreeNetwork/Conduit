import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { X } from "lucide-react";
import { MatrixError, describeError } from "../core";
import { Field } from "./Field";
import { useClient } from "./hooks";

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  testId: string;
}

/**
 * Native <dialog> as a modal: the browser supplies the focus trap, Escape,
 * inertness of the page behind and the top layer. Focus returns to the
 * element that opened it.
 */
export function Dialog({ open, onClose, title, description, children, testId }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const titleId = `${testId}-title`;
  const descId = description ? `${testId}-desc` : undefined;

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      opener.current = document.activeElement as HTMLElement | null;
      dialog.showModal();
      const first = dialog.querySelector<HTMLElement>("[data-autofocus], input, textarea, button:not(.dialog-close)");
      first?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const onDialogClose = () => {
      const target = opener.current;
      opener.current = null;
      const active = document.activeElement;
      const focusLost = !active || active === document.body || dialog.contains(active);
      if (focusLost && target?.isConnected) target.focus();
      onClose();
    };
    dialog.addEventListener("close", onDialogClose);
    return () => dialog.removeEventListener("close", onDialogClose);
  }, [onClose]);

  return (
    <dialog ref={ref} className="dialog" aria-labelledby={titleId} aria-describedby={descId} data-testid={testId}>
      {open && (
        <div className="dialog-plate">
          <header className="dialog-head">
            <h2 id={titleId} className="plate-subtitle">
              {title}
            </h2>
            <button type="button" className="icon-button dialog-close" onClick={() => ref.current?.close()} aria-label="Close">
              <X size={18} aria-hidden="true" />
            </button>
          </header>
          {description && (
            <p id={descId} className="dialog-desc">
              {description}
            </p>
          )}
          {children}
        </div>
      )}
    </dialog>
  );
}

function DialogActions({ pending, submitLabel, pendingLabel, onCancel, danger, testId }: {
  pending: boolean;
  submitLabel: string;
  pendingLabel: string;
  onCancel: () => void;
  danger?: boolean;
  testId: string;
}) {
  return (
    <div className="dialog-actions">
      <button type="button" className="button button-quiet" onClick={onCancel}>
        Cancel
      </button>
      <button
        type="submit"
        className={`button ${danger ? "button-danger" : "button-primary"}`}
        disabled={pending}
        aria-busy={pending}
        data-testid={testId}
      >
        {pending ? pendingLabel : submitLabel}
      </button>
    </div>
  );
}

function ErrorCallout({ error, testId }: { error?: string; testId: string }) {
  if (!error) return null;
  return (
    <p className="callout callout-error" role="alert" data-testid={testId}>
      {error}
    </p>
  );
}

export function CreateRoomDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (roomId: string) => void }) {
  const client = useClient();
  const [name, setName] = useState("");
  const [topic, setTopic] = useState("");
  const [visibility, setVisibility] = useState<"private" | "public">("private");
  const [nameError, setNameError] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (open) {
      setName("");
      setTopic("");
      setVisibility("private");
      setError(undefined);
      setNameError(undefined);
    }
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) {
      setNameError("Give the room a name so people can find it.");
      document.getElementById("create-name")?.focus();
      return;
    }
    setNameError(undefined);
    setPending(true);
    setError(undefined);
    try {
      const roomId = await client.createRoom({ name, topic, visibility });
      onCreated(roomId);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title="New room" testId="create-room-dialog">
      <form onSubmit={submit} noValidate>
        <Field id="create-name" label="Name" value={name} onChange={setName} error={nameError} testId="create-room-name" />
        <Field id="create-topic" label="Topic" hint="Optional. What the room is for." value={topic} onChange={setTopic} testId="create-room-topic" />
        <fieldset className="choice-group">
          <legend className="field-label">Who can join</legend>
          <label className="choice">
            <input
              type="radio"
              name="visibility"
              value="private"
              checked={visibility === "private"}
              onChange={() => setVisibility("private")}
              data-testid="create-room-private"
            />
            <span>
              <span className="choice-title">Only people you invite</span>
              <span className="choice-hint">A private room. New people need an invite.</span>
            </span>
          </label>
          <label className="choice">
            <input
              type="radio"
              name="visibility"
              value="public"
              checked={visibility === "public"}
              onChange={() => setVisibility("public")}
              data-testid="create-room-public"
            />
            <span>
              <span className="choice-title">Anyone on the server</span>
              <span className="choice-hint">A public room, listed in the room directory.</span>
            </span>
          </label>
        </fieldset>
        <ErrorCallout error={error} testId="create-room-error" />
        <DialogActions pending={pending} submitLabel="Create room" pendingLabel="Creating…" onCancel={onClose} testId="create-room-submit" />
      </form>
    </Dialog>
  );
}

export function JoinRoomDialog({ open, onClose, onJoined }: { open: boolean; onClose: () => void; onJoined: (roomId: string) => void }) {
  const client = useClient();
  const [address, setAddress] = useState("");
  const [fieldError, setFieldError] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (open) {
      setAddress("");
      setError(undefined);
      setFieldError(undefined);
    }
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const value = address.trim();
    if (!/^[#!][^:\s]+:\S+$/.test(value)) {
      setFieldError("Enter a room address like #general:example.org or a room ID like !abc:example.org.");
      document.getElementById("join-address")?.focus();
      return;
    }
    setFieldError(undefined);
    setPending(true);
    setError(undefined);
    try {
      onJoined(await client.joinRoom(value));
    } catch (e) {
      if (e instanceof MatrixError && e.errcode === "M_NOT_FOUND") setError("No room was found at that address.");
      else if (e instanceof MatrixError && e.errcode === "M_FORBIDDEN") setError("You need an invite to join that room.");
      else setError(describeError(e));
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title="Join a room" testId="join-room-dialog">
      <form onSubmit={submit} noValidate>
        <Field
          id="join-address"
          label="Room address or ID"
          placeholder="#general:example.org"
          value={address}
          onChange={setAddress}
          error={fieldError}
          autoCapitalize="none"
          spellCheck={false}
          testId="join-room-address"
        />
        <ErrorCallout error={error} testId="join-room-error" />
        <DialogActions pending={pending} submitLabel="Join" pendingLabel="Joining…" onCancel={onClose} testId="join-room-submit" />
      </form>
    </Dialog>
  );
}

export function InviteDialog({ open, roomId, roomName, onClose }: { open: boolean; roomId: string; roomName: string; onClose: () => void }) {
  const client = useClient();
  const [userId, setUserId] = useState("");
  const [fieldError, setFieldError] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (open) {
      setUserId("");
      setError(undefined);
      setFieldError(undefined);
    }
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const value = userId.trim();
    if (!/^@[^:\s]+:\S+$/.test(value)) {
      setFieldError("Enter a full Matrix ID like @sam:example.org.");
      document.getElementById("invite-user")?.focus();
      return;
    }
    const existing = client.getRoom(roomId)?.member(value)?.membership;
    if (existing === "join" || existing === "invite") {
      setFieldError(existing === "join" ? "They're already in this room." : "They already have an invite.");
      return;
    }
    setFieldError(undefined);
    setPending(true);
    setError(undefined);
    try {
      await client.invite(roomId, value);
      onClose();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title={`Invite to ${roomName}`} testId="invite-dialog">
      <form onSubmit={submit} noValidate>
        <Field
          id="invite-user"
          label="Matrix ID"
          placeholder="@sam:example.org"
          value={userId}
          onChange={setUserId}
          error={fieldError}
          autoCapitalize="none"
          spellCheck={false}
          testId="invite-user-id"
        />
        <ErrorCallout error={error} testId="invite-error" />
        <DialogActions pending={pending} submitLabel="Send invite" pendingLabel="Inviting…" onCancel={onClose} testId="invite-submit" />
      </form>
    </Dialog>
  );
}

export function LeaveDialog({ open, roomId, roomName, onClose, onLeft }: {
  open: boolean;
  roomId: string;
  roomName: string;
  onClose: () => void;
  onLeft: () => void;
}) {
  const client = useClient();
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);
  const isPublic = client.getRoom(roomId)?.isPublic;

  useEffect(() => {
    if (open) setError(undefined);
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      await client.leaveRoom(roomId);
      onLeft();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Leave ${roomName}?`}
      description={
        isPublic
          ? "You can rejoin later from its address."
          : "This room is invite-only. You will need a new invite to come back."
      }
      testId="leave-dialog"
    >
      <form onSubmit={submit}>
        <ErrorCallout error={error} testId="leave-error" />
        <DialogActions pending={pending} submitLabel="Leave room" pendingLabel="Leaving…" onCancel={onClose} danger testId="leave-submit" />
      </form>
    </Dialog>
  );
}
