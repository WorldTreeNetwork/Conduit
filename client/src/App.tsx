import { useCallback, useEffect, useMemo, useState } from "react";
import {
  LocalStorageStore,
  MatrixClient,
  clearStoredSession,
  loadStoredSession,
  saveSession,
  type Session,
} from "./core";
import { installTestHook } from "./testHook";
import { ClientContext } from "./ui/hooks";
import { Shell } from "./ui/Shell";
import { SignIn } from "./ui/SignIn";
import { applyTheme, loadTheme } from "./ui/theme";

export function App() {
  const store = useMemo(() => new LocalStorageStore(), []);
  const [session, setSession] = useState<Session | undefined>(() => loadStoredSession(store));
  const [notice, setNotice] = useState<string | undefined>(undefined);

  useEffect(() => applyTheme(loadTheme()), []);

  const client = useMemo(() => (session ? new MatrixClient({ session, store }) : null), [session, store]);

  useEffect(() => {
    installTestHook(client);
    if (!client) return;
    client.onLoggedOut = (reason) => {
      setNotice(reason);
      setSession(undefined);
    };
    client.start();
    const online = () => client.sync.retryNow();
    window.addEventListener("online", online);
    return () => {
      window.removeEventListener("online", online);
      void client.stop();
    };
  }, [client]);

  const onSignedIn = useCallback(
    (next: Session) => {
      clearStoredSession(store);
      saveSession(store, next);
      setNotice(undefined);
      window.location.hash = "#/";
      setSession(next);
    },
    [store],
  );

  const onSignedOut = useCallback(async () => {
    if (client) await client.logout();
    clearStoredSession(store);
    window.location.hash = "";
    setNotice("You have signed out.");
    setSession(undefined);
  }, [client, store]);

  if (!client) return <SignIn onSignedIn={onSignedIn} notice={notice} />;
  return (
    <ClientContext.Provider value={client}>
      <Shell onSignOut={onSignedOut} />
    </ClientContext.Provider>
  );
}
