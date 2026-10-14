import { useEffect, useState } from "react";
import { WifiOff } from "lucide-react";
import { useClient, useClientVersion } from "./hooks";

const LINE_LABEL = {
  stopped: "Offline",
  connecting: "Connecting",
  live: "Line clear",
  reconnecting: "Line down",
  error: "Signed out",
} as const;

/** The always-visible service state at the foot of the destination board. */
export function LineStatus() {
  const client = useClient();
  useClientVersion();
  const { state } = client.syncHealth;
  return (
    <p className={`line-status line-${state}`} data-testid="sync-status" data-state={state}>
      <span className="line-lamp" aria-hidden="true" />
      {LINE_LABEL[state]}
    </p>
  );
}

/** Banner over the conversation while sync is failing. */
export function ConnectionBanner() {
  const client = useClient();
  useClientVersion();
  const health = client.syncHealth;
  const reconnecting = health.state === "reconnecting";
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!reconnecting) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [reconnecting]);

  // The live region is always mounted so the announcement is reliable.
  return (
    <div className="banner-region" role="status" aria-live="polite" data-testid="connection-banner-region">
      {reconnecting && (
        <div className="banner banner-caution" data-testid="connection-banner">
          <WifiOff size={18} aria-hidden="true" />
          <p className="banner-text">
            <strong>Reconnecting.</strong> {health.lastError ?? "The server isn't answering."}{" "}
            {health.nextRetryAt !== undefined && health.nextRetryAt > now && (
              <span className="banner-countdown">
                Trying again in {Math.ceil((health.nextRetryAt - now) / 1000)}s.
              </span>
            )}{" "}
            Anything that fails to send stays here for you to retry.
          </p>
          <button type="button" className="button button-small" onClick={() => client.sync.retryNow()} data-testid="retry-sync">
            Retry now
          </button>
        </div>
      )}
    </div>
  );
}
