// Account and session management: devices, password, deactivation, and the
// soft-logout re-authentication screen.
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Laptop, Pencil } from "lucide-react";
import { MatrixError, describeError, type DeviceInfo } from "../core";
import { Dialog } from "./Dialogs";
import { Field } from "./Field";
import { useClient } from "./hooks";
import { Mark } from "./Mark";

function passwordError(e: unknown): string {
  if (e instanceof MatrixError && (e.errcode === "M_FORBIDDEN" || e.httpStatus === 401)) return "That password is not right.";
  return describeError(e);
}

function lastSeen(device: DeviceInfo): string {
  const parts: string[] = [];
  if (device.last_seen_ts) {
    parts.push(
      `Last active ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(device.last_seen_ts))}`,
    );
  }
  if (device.last_seen_ip) parts.push(device.last_seen_ip);
  return parts.join(" · ") || "No activity recorded";
}

/** Ask for the account password, then run an action (UIA m.login.password). */
function PasswordConfirmDialog({
  open,
  title,
  description,
  submitLabel,
  pendingLabel,
  onConfirm,
  onClose,
  testId,
}: {
  open: boolean;
  title: string;
  description: string;
  submitLabel: string;
  pendingLabel: string;
  onConfirm: (password: string) => Promise<void>;
  onClose: () => void;
  testId: string;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (open) {
      setPassword("");
      setError(undefined);
    }
  }, [open]);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password) {
      setError("Enter your password to confirm.");
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      await onConfirm(password);
      onClose();
    } catch (err) {
      setError(passwordError(err));
    } finally {
      setPending(false);
    }
  }
  return (
    <Dialog open={open} onClose={onClose} title={title} description={description} testId={testId}>
      <form onSubmit={submit} noValidate>
        <Field
          id={`${testId}-password`}
          label="Your password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={setPassword}
          error={error}
          testId={`${testId}-password`}
        />
        <div className="dialog-actions">
          <button type="button" className="button button-quiet" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="button button-danger" disabled={pending} aria-busy={pending} data-testid={`${testId}-submit`}>
            {pending ? pendingLabel : submitLabel}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function DevicesSection() {
  const client = useClient();
  const [devices, setDevices] = useState<DeviceInfo[] | null>(null);
  const [error, setError] = useState<string | undefined>(undefined);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [confirm, setConfirm] = useState<string[] | null>(null);
  const [status, setStatus] = useState("");

  const load = useCallback(() => {
    setError(undefined);
    client
      .listDevices()
      .then((list) => setDevices(list.sort((a, b) => (b.last_seen_ts ?? 0) - (a.last_seen_ts ?? 0))))
      .catch((e) => setError(describeError(e)));
  }, [client]);
  useEffect(load, [load]);

  const current = client.session.deviceId;
  const others = (devices ?? []).filter((d) => d.device_id !== current);
  const mine = (devices ?? []).find((d) => d.device_id === current);

  async function rename(e: FormEvent, deviceId: string) {
    e.preventDefault();
    try {
      await client.renameDevice(deviceId, newName);
      setRenaming(null);
      setStatus("Device renamed.");
      load();
    } catch (err) {
      setStatus(describeError(err));
    }
  }

  function row(device: DeviceInfo, isCurrent: boolean) {
    const name = device.display_name || device.device_id;
    return (
      <li key={device.device_id} className="device" data-testid="device-row" data-device-id={device.device_id} data-current={isCurrent}>
        <Laptop size={20} aria-hidden="true" />
        <div className="device-text">
          {renaming === device.device_id ? (
            <form className="device-rename" onSubmit={(e) => void rename(e, device.device_id)}>
              <label className="visually-hidden" htmlFor={`rename-${device.device_id}`}>
                New name for {name}
              </label>
              <input
                id={`rename-${device.device_id}`}
                className="input input-compact"
                value={newName}
                autoFocus
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => e.key === "Escape" && setRenaming(null)}
                data-testid="device-rename-input"
              />
              <button type="submit" className="button button-small button-primary" data-testid="device-rename-save">
                Save
              </button>
            </form>
          ) : (
            <span className="device-name">
              {name}
              {isCurrent && <span className="badge badge-current">This device</span>}
            </span>
          )}
          <span className="device-meta">
            {device.device_id} · {lastSeen(device)}
          </span>
        </div>
        <div className="device-actions">
          {renaming !== device.device_id && (
            <button
              type="button"
              className="icon-button"
              aria-label={`Rename ${name}`}
              onClick={() => {
                setRenaming(device.device_id);
                setNewName(device.display_name ?? "");
              }}
              data-testid="device-rename"
            >
              <Pencil size={16} aria-hidden="true" />
            </button>
          )}
          {!isCurrent && (
            <button type="button" className="button button-small button-quiet" onClick={() => setConfirm([device.device_id])} data-testid="device-sign-out">
              Sign out
            </button>
          )}
        </div>
      </li>
    );
  }

  return (
    <section className="settings-section" aria-labelledby="devices-heading" data-testid="devices">
      <h2 id="devices-heading" className="plate-subtitle">
        Where you're signed in
      </h2>
      {error && (
        <p className="callout callout-error" role="alert">
          Couldn't load your devices. {error}{" "}
          <button type="button" className="link-button" onClick={load}>
            Try again
          </button>
        </p>
      )}
      {!devices && !error && (
        <p className="muted" role="status" data-testid="devices-loading">
          Loading devices…
        </p>
      )}
      {devices && (
        <ul className="device-list">
          {mine && row(mine, true)}
          {others.map((d) => row(d, false))}
        </ul>
      )}
      {others.length > 1 && (
        <button type="button" className="button button-danger" onClick={() => setConfirm(others.map((d) => d.device_id))} data-testid="sign-out-others">
          Sign out all other devices
        </button>
      )}
      <p role="status" className="muted" data-testid="devices-status">
        {status}
      </p>
      <PasswordConfirmDialog
        open={confirm !== null}
        title={confirm && confirm.length > 1 ? `Sign out ${confirm.length} devices?` : "Sign out this device?"}
        description="It will need to sign in again. Confirm with your password."
        submitLabel="Sign out"
        pendingLabel="Signing out…"
        testId="confirm-device-signout"
        onClose={() => setConfirm(null)}
        onConfirm={async (password) => {
          await client.deleteDevices(confirm ?? [], password);
          setStatus(confirm && confirm.length > 1 ? "Other devices signed out." : "Device signed out.");
          load();
        }}
      />
    </section>
  );
}

export function PasswordSection() {
  const client = useClient();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [logoutOthers, setLogoutOthers] = useState(true);
  const [errors, setErrors] = useState<{ current?: string; next?: string; confirm?: string }>({});
  const [status, setStatus] = useState<{ ok?: string; error?: string }>({});
  const [pending, setPending] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const found = {
      current: current ? undefined : "Enter your current password.",
      next: next.length >= 8 ? undefined : "Use at least 8 characters.",
      confirm: confirm === next ? undefined : "The passwords don't match.",
    };
    setErrors(found);
    setStatus({});
    if (found.current || found.next || found.confirm) return;
    setPending(true);
    try {
      await client.changePassword(current, next, logoutOthers);
      setCurrent("");
      setNext("");
      setConfirm("");
      setStatus({ ok: logoutOthers ? "Password changed. Your other devices were signed out." : "Password changed." });
    } catch (err) {
      const message = passwordError(err);
      if (message === "That password is not right.") setErrors({ current: message });
      else setStatus({ error: message });
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="settings-section" aria-labelledby="password-heading">
      <h2 id="password-heading" className="plate-subtitle">
        Password
      </h2>
      <form className="settings-form" onSubmit={submit} noValidate data-testid="password-form">
        <Field id="pw-current" label="Current password" type="password" autoComplete="current-password" value={current} onChange={setCurrent} error={errors.current} testId="password-current" />
        <Field id="pw-new" label="New password" type="password" autoComplete="new-password" value={next} onChange={setNext} error={errors.next} testId="password-new" />
        <Field id="pw-confirm" label="Confirm new password" type="password" autoComplete="new-password" value={confirm} onChange={setConfirm} error={errors.confirm} testId="password-confirm" />
        <label className="check">
          <input type="checkbox" checked={logoutOthers} onChange={(e) => setLogoutOthers(e.target.checked)} data-testid="password-logout-others" />
          Sign out my other devices
        </label>
        <div className="settings-row">
          <button type="submit" className="button button-primary" disabled={pending} aria-busy={pending} data-testid="password-save">
            {pending ? "Changing…" : "Change password"}
          </button>
          <span role="status" className={status.error ? "field-error" : "muted"} data-testid="password-status">
            {status.error ?? status.ok ?? ""}
          </span>
        </div>
      </form>
    </section>
  );
}

export function DeactivateSection({ onDeactivated }: { onDeactivated: () => void }) {
  const client = useClient();
  const [open, setOpen] = useState(false);
  const [erase, setErase] = useState(false);
  return (
    <section className="settings-section settings-danger" aria-labelledby="deactivate-heading">
      <h2 id="deactivate-heading" className="plate-subtitle">
        Deactivate account
      </h2>
      <p className="muted">
        This permanently closes your account: you leave every room, all your devices are signed out, and the username can't be
        used again.
      </p>
      <label className="check">
        <input type="checkbox" checked={erase} onChange={(e) => setErase(e.target.checked)} data-testid="deactivate-erase" />
        Also erase my profile and hide my messages from people who join later
      </label>
      <button type="button" className="button button-danger" onClick={() => setOpen(true)} data-testid="deactivate-open">
        Deactivate account
      </button>
      <PasswordConfirmDialog
        open={open}
        title="Deactivate your account?"
        description="This cannot be undone. Confirm with your password."
        submitLabel="Deactivate"
        pendingLabel="Deactivating…"
        testId="confirm-deactivate"
        onClose={() => setOpen(false)}
        onConfirm={async (password) => {
          await client.deactivate(password, erase);
          onDeactivated();
        }}
      />
    </section>
  );
}

/** Shown after a soft logout: sign in again on this device, keeping its data. */
export function ReauthScreen({ onSignOut }: { onSignOut: () => Promise<void> }) {
  const client = useClient();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.focus();
    document.title = "Session expired · Conduit";
  }, []);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password) {
      setError("Enter your password.");
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      await client.reauthenticate(password);
    } catch (err) {
      setError(passwordError(err));
    } finally {
      setPending(false);
    }
  }
  return (
    <div className="signin" data-testid="reauth">
      <main className="signin-plate" aria-labelledby="reauth-heading">
        <div className="signin-body">
          <div className="signin-brand">
            <Mark />
            <span className="signin-wordmark">Conduit</span>
          </div>
          <h1 id="reauth-heading" ref={headingRef} tabIndex={-1} className="signin-title">
            Your session expired
          </h1>
          <p className="muted reauth-copy">
            Sign in again as <strong>{client.userId}</strong> to continue on this device. Your rooms and unsent messages are kept.
          </p>
          <form onSubmit={submit} noValidate>
            <Field id="reauth-password" label="Password" type="password" autoComplete="current-password" value={password} onChange={setPassword} error={error} testId="reauth-password" />
            <button type="submit" className="button button-primary button-block" disabled={pending} aria-busy={pending} data-testid="reauth-submit">
              {pending ? "Signing in…" : "Continue"}
            </button>
          </form>
          <p className="signin-switch">
            <button type="button" className="link-button" onClick={() => void onSignOut()} data-testid="reauth-sign-out">
              Sign out instead
            </button>
          </p>
        </div>
      </main>
    </div>
  );
}
