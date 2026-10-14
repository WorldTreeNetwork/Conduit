import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import {
  HttpClient,
  describeError,
  discoverHomeserver,
  loginWithPassword,
  realClock,
  register,
  validateUsername,
  type Session,
} from "../core";
import { configuredHomeserver, homeserverPinned } from "../config";
import { Field } from "./Field";
import { Mark } from "./Mark";

type Mode = "login" | "register";

interface Errors {
  homeserver?: string;
  username?: string;
  password?: string;
  confirm?: string;
}

export function SignIn({ onSignedIn, notice }: { onSignedIn: (session: Session) => void; notice?: string }) {
  const [mode, setMode] = useState<Mode>("login");
  const [homeserver, setHomeserver] = useState(configuredHomeserver);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errors, setErrors] = useState<Errors>({});
  const [formError, setFormError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState<string | undefined>(undefined);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const pinned = homeserverPinned();
  const errorId = useId();

  useEffect(() => {
    headingRef.current?.focus();
    document.title = mode === "login" ? "Sign in · Conduit" : "Create account · Conduit";
  }, [mode]);

  function validate(): Errors {
    const next: Errors = {};
    if (!homeserver.trim()) next.homeserver = "Enter your homeserver address.";
    if (mode === "register") {
      next.username = validateUsername(username);
      if (password.length < 8) next.password = "Use at least 8 characters.";
      if (confirm !== password) next.confirm = "The passwords don't match.";
    } else {
      if (!username.trim()) next.username = "Enter your username.";
      if (!password) next.password = "Enter your password.";
    }
    return Object.fromEntries(Object.entries(next).filter(([, v]) => v)) as Errors;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const found = validate();
    setErrors(found);
    setFormError(undefined);
    const first = Object.keys(found)[0];
    if (first) {
      document.getElementById(`signin-${first}`)?.focus();
      return;
    }
    try {
      setPending("Finding your homeserver…");
      const discovered = await discoverHomeserver(username.startsWith("@") && !pinned ? username : homeserver, {
        clock: realClock,
      });
      if (discovered.kind !== "ok") {
        setErrors({ homeserver: discovered.reason });
        document.getElementById("signin-homeserver")?.focus();
        return;
      }
      const http = new HttpClient({ baseUrl: discovered.baseUrl, clock: realClock });
      setPending(mode === "login" ? "Signing in…" : "Creating your account…");
      const session =
        mode === "login" ? await loginWithPassword(http, username, password) : await register(http, username, password);
      onSignedIn(session);
    } catch (error) {
      setFormError(
        mode === "login" && error instanceof Error && "errcode" in error && error.errcode === "M_FORBIDDEN"
          ? "That username and password don't match."
          : describeError(error),
      );
    } finally {
      setPending(undefined);
    }
  }

  function switchMode(next: Mode) {
    setMode(next);
    setErrors({});
    setFormError(undefined);
    setConfirm("");
  }

  return (
    <div className="signin">
      <main className="signin-plate" aria-labelledby="signin-heading">
        <div className="signin-brand">
          <Mark />
          <span className="signin-wordmark">Conduit</span>
        </div>
        <h1 id="signin-heading" ref={headingRef} tabIndex={-1} className="signin-title">
          {mode === "login" ? "Sign in" : "Create an account"}
        </h1>
        {notice && (
          <p className="callout callout-info" role="status" data-testid="signin-notice">
            {notice}
          </p>
        )}
        <form
          onSubmit={submit}
          noValidate
          aria-describedby={formError ? errorId : undefined}
          data-testid={mode === "login" ? "login-form" : "register-form"}
        >
          {!pinned ? (
            <Field
              id="signin-homeserver"
              label="Homeserver"
              hint="The address of your Matrix server, like https://matrix.example.org"
              value={homeserver}
              onChange={setHomeserver}
              error={errors.homeserver}
              autoComplete="url"
              inputMode="url"
              testId="homeserver-input"
            />
          ) : (
            <p className="signin-server" data-testid="homeserver-pinned">
              Server <span className="mono-ish">{homeserver}</span>
            </p>
          )}
          {pinned && errors.homeserver && (
            <p className="field-error" role="alert">
              {errors.homeserver}
            </p>
          )}
          <Field
            id="signin-username"
            label="Username"
            hint={mode === "register" ? "Lowercase letters, digits and . _ = - / +" : undefined}
            value={username}
            onChange={setUsername}
            error={errors.username}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            testId="username-input"
          />
          <Field
            id="signin-password"
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            error={errors.password}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            testId="password-input"
          />
          {mode === "register" && (
            <Field
              id="signin-confirm"
              label="Confirm password"
              type="password"
              value={confirm}
              onChange={setConfirm}
              error={errors.confirm}
              autoComplete="new-password"
              testId="confirm-input"
            />
          )}
          {formError && (
            <p id={errorId} className="callout callout-error" role="alert" data-testid="signin-error">
              {formError}
            </p>
          )}
          <button
            type="submit"
            className="button button-primary button-block"
            disabled={!!pending}
            aria-busy={!!pending}
            data-testid="signin-submit"
          >
            {pending ?? (mode === "login" ? "Sign in" : "Create account")}
          </button>
        </form>
        <p className="signin-switch">
          {mode === "login" ? "New here?" : "Already have an account?"}{" "}
          <button
            type="button"
            className="link-button"
            onClick={() => switchMode(mode === "login" ? "register" : "login")}
            data-testid="signin-switch-mode"
          >
            {mode === "login" ? "Create an account" : "Sign in instead"}
          </button>
        </p>
      </main>
    </div>
  );
}
