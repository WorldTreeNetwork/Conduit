// Runtime configuration.
//
// Homeserver: `?hs=<url>` wins (e2e points the client at its ephemeral
// server this way), then VITE_CONDUIT_HOMESERVER, then the page's own origin
// when served by a homeserver, else a localhost default.

export function configuredHomeserver(): string {
  try {
    const fromQuery = new URLSearchParams(window.location.search).get("hs");
    if (fromQuery) return fromQuery;
  } catch {
    /* not in a browser */
  }
  const fromEnv = import.meta.env.VITE_CONDUIT_HOMESERVER as string | undefined;
  if (fromEnv) return fromEnv;
  return "http://localhost:8008";
}

/** Whether `?hs=` explicitly pinned the homeserver (hides the field). */
export function homeserverPinned(): boolean {
  try {
    return new URLSearchParams(window.location.search).has("hs");
  } catch {
    return false;
  }
}

/**
 * window.__conduitClient is installed only in dev builds or when the build
 * sets VITE_CONDUIT_TEST_HOOKS=1. Production bundles never expose it.
 */
export const testHooksEnabled: boolean =
  import.meta.env.DEV || import.meta.env.VITE_CONDUIT_TEST_HOOKS === "1";
