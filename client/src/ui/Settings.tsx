import { useEffect, useRef, useState, type FormEvent } from "react";
import { describeError } from "../core";
import { Field } from "./Field";
import { useClient } from "./hooks";
import { loadTheme, saveTheme, type ThemeChoice } from "./theme";

export function Settings({ onSignOut, onProfileChanged }: { onSignOut: () => Promise<void>; onProfileChanged: (name: string) => void }) {
  const client = useClient();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [name, setName] = useState("");
  const [loaded, setLoaded] = useState<"loading" | "ready" | "error">("loading");
  const [loadError, setLoadError] = useState<string | undefined>(undefined);
  const [saving, setSaving] = useState(false);
  const [saveState, setSaveState] = useState<{ ok?: string; error?: string }>({});
  const [theme, setTheme] = useState<ThemeChoice>(loadTheme);
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    headingRef.current?.focus();
    document.title = "Settings · Conduit";
  }, []);

  const load = () => {
    setLoaded("loading");
    client
      .getProfile(client.userId)
      .then((p) => {
        setName(p.displayname ?? "");
        setLoaded("ready");
      })
      .catch((e) => {
        setLoadError(describeError(e));
        setLoaded("error");
      });
  };
  useEffect(load, [client]);

  async function saveName(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setSaveState({});
    try {
      await client.setDisplayName(name);
      onProfileChanged(name.trim());
      setSaveState({ ok: "Display name saved." });
    } catch (e) {
      setSaveState({ error: describeError(e) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="settings" aria-labelledby="settings-heading" data-testid="settings">
      <a href="#/" className="back-link link-button">
        All rooms
      </a>
      <h1 id="settings-heading" ref={headingRef} tabIndex={-1} className="plate-title">
        Settings
      </h1>

      <section className="settings-section" aria-labelledby="profile-heading">
        <h2 id="profile-heading" className="plate-subtitle">
          Profile
        </h2>
        {loaded === "loading" && (
          <p className="muted" role="status" data-testid="profile-loading">
            Loading your profile…
          </p>
        )}
        {loaded === "error" && (
          <p className="callout callout-error" role="alert">
            Couldn't load your profile. {loadError}{" "}
            <button type="button" className="link-button" onClick={load}>
              Try again
            </button>
          </p>
        )}
        {loaded === "ready" && (
          <form onSubmit={saveName} className="settings-form">
            <Field
              id="settings-displayname"
              label="Display name"
              hint="Shown to people in your rooms instead of your Matrix ID."
              value={name}
              onChange={setName}
              testId="displayname-input"
            />
            <div className="settings-row">
              <button type="submit" className="button button-primary" disabled={saving} aria-busy={saving} data-testid="displayname-save">
                {saving ? "Saving…" : "Save"}
              </button>
              <span role="status" className={saveState.error ? "field-error" : "muted"} data-testid="displayname-status">
                {saveState.error ?? saveState.ok ?? ""}
              </span>
            </div>
          </form>
        )}
      </section>

      <section className="settings-section" aria-labelledby="appearance-heading">
        <h2 id="appearance-heading" className="plate-subtitle">
          Appearance
        </h2>
        <fieldset className="choice-group choice-inline">
          <legend className="field-label">Theme</legend>
          {(["system", "light", "dark"] as const).map((choice) => (
            <label key={choice} className="choice">
              <input
                type="radio"
                name="theme"
                value={choice}
                checked={theme === choice}
                onChange={() => {
                  setTheme(choice);
                  saveTheme(choice);
                }}
                data-testid={`theme-${choice}`}
              />
              <span className="choice-title">{choice === "system" ? "Match system" : choice === "light" ? "Day" : "Night"}</span>
            </label>
          ))}
        </fieldset>
      </section>

      <section className="settings-section" aria-labelledby="session-heading">
        <h2 id="session-heading" className="plate-subtitle">
          This session
        </h2>
        <dl className="facts">
          <dt>Matrix ID</dt>
          <dd data-testid="settings-user-id">{client.userId}</dd>
          <dt>Device</dt>
          <dd data-testid="settings-device-id">{client.session.deviceId}</dd>
          <dt>Homeserver</dt>
          <dd>{client.session.homeserverUrl}</dd>
        </dl>
        <p className="muted">
          Device management, notification settings and end-to-end encryption are not available in this version yet.
        </p>
        <button
          type="button"
          className="button button-danger"
          disabled={signingOut}
          aria-busy={signingOut}
          onClick={async () => {
            setSigningOut(true);
            await onSignOut();
          }}
          data-testid="sign-out"
        >
          {signingOut ? "Signing out…" : "Sign out"}
        </button>
      </section>
    </section>
  );
}
