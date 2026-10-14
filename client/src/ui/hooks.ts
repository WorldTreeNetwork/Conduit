import { createContext, useCallback, useContext, useEffect, useState, useSyncExternalStore } from "react";
import type { MatrixClient } from "../core";

export const ClientContext = createContext<MatrixClient | null>(null);

export function useClient(): MatrixClient {
  const client = useContext(ClientContext);
  if (!client) throw new Error("useClient outside ClientContext");
  return client;
}

/** Re-render whenever the client's model changes; returns the version. */
export function useClientVersion(): number {
  const client = useClient();
  return useSyncExternalStore(client.subscribe, client.getVersion);
}

export type Route = { name: "home" } | { name: "room"; roomId: string } | { name: "settings" };

export function parseHash(hash: string): Route {
  const path = hash.replace(/^#/, "");
  const room = /^\/room\/(.+)$/.exec(path);
  if (room?.[1]) {
    try {
      return { name: "room", roomId: decodeURIComponent(room[1]) };
    } catch {
      return { name: "home" };
    }
  }
  if (path === "/settings") return { name: "settings" };
  return { name: "home" };
}

export function routeHref(route: Route): string {
  switch (route.name) {
    case "room":
      return `#/room/${encodeURIComponent(route.roomId)}`;
    case "settings":
      return "#/settings";
    default:
      return "#/";
  }
}

export function useHashRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onHash = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const navigate = useCallback((next: Route) => {
    const href = routeHref(next);
    if (window.location.hash !== href) window.location.hash = href;
    setRoute(next);
  }, []);
  return [route, navigate];
}

/** Track an async action's pending/error state for a button or form. */
export function useAction<A extends unknown[], T>(
  action: (...args: A) => Promise<T>,
): { run: (...args: A) => Promise<T | undefined>; pending: boolean; error: unknown; reset: () => void } {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(undefined);
  const run = useCallback(
    async (...args: A) => {
      setPending(true);
      setError(undefined);
      try {
        return await action(...args);
      } catch (e) {
        setError(e);
        return undefined;
      } finally {
        setPending(false);
      }
    },
    [action],
  );
  return { run, pending, error, reset: () => setError(undefined) };
}

export function usePrefersReducedMotion(): boolean {
  const query = "(prefers-reduced-motion: reduce)";
  const [reduced, setReduced] = useState(() => typeof window !== "undefined" && window.matchMedia?.(query).matches);
  useEffect(() => {
    const media = window.matchMedia?.(query);
    if (!media) return;
    const onChange = () => setReduced(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);
  return reduced;
}
