// Public room directory and user search.
import { useEffect, useState } from "react";
import { describeError, type PublicRoom } from "../core";
import { useClient, useClientVersion } from "./hooks";
import { initialOf, tintIndex } from "./format";

/** Browse and search the server's published rooms. */
export function RoomDirectory({ onJoined }: { onJoined: (roomId: string) => void }) {
  const client = useClient();
  useClientVersion();
  const [term, setTerm] = useState("");
  const [query, setQuery] = useState("");
  const [rooms, setRooms] = useState<PublicRoom[]>([]);
  const [next, setNext] = useState<string | undefined>(undefined);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | undefined>(undefined);
  const [joining, setJoining] = useState<string | null>(null);
  const [joinError, setJoinError] = useState<string | undefined>(undefined);

  // Debounce typing into the search term.
  useEffect(() => {
    const timer = setTimeout(() => setQuery(term.trim()), 300);
    return () => clearTimeout(timer);
  }, [term]);

  useEffect(() => {
    let cancelled = false;
    setStatus("loading");
    client
      .publicRooms({ term: query || undefined })
      .then((page) => {
        if (cancelled) return;
        setRooms(page.chunk ?? []);
        setNext(page.next_batch);
        setStatus("ready");
      })
      .catch((e) => {
        if (cancelled) return;
        setError(describeError(e));
        setStatus("error");
      });
    return () => {
      cancelled = true;
    };
  }, [client, query]);

  async function more() {
    if (!next) return;
    try {
      const page = await client.publicRooms({ term: query || undefined, since: next });
      setRooms((r) => [...r, ...(page.chunk ?? [])]);
      setNext(page.next_batch);
    } catch (e) {
      setError(describeError(e));
    }
  }

  return (
    <section className="directory" aria-labelledby="directory-heading" data-testid="room-directory">
      <h3 id="directory-heading" className="panel-label">
        Public rooms on this server
      </h3>
      <label className="visually-hidden" htmlFor="directory-search">
        Search public rooms
      </label>
      <input
        id="directory-search"
        className="input"
        type="search"
        placeholder="Search public rooms"
        value={term}
        onChange={(e) => setTerm(e.target.value)}
        data-testid="directory-search"
      />
      <div className="directory-results" aria-busy={status === "loading"} aria-live="polite">
        {status === "loading" && rooms.length === 0 && (
          <p className="muted" data-testid="directory-loading">
            Looking for rooms…
          </p>
        )}
        {status === "error" && (
          <p className="callout callout-error" role="alert" data-testid="directory-error">
            Couldn't load the directory. {error}
          </p>
        )}
        {status === "ready" && rooms.length === 0 && (
          <p className="muted" data-testid="directory-empty">
            {query ? `No public rooms match “${query}”.` : "No public rooms yet."}
          </p>
        )}
        {rooms.length > 0 && (
          <ul className="directory-list">
            {rooms.map((room) => {
              const name = room.name || room.canonical_alias || room.room_id;
              const joined = client.getRoom(room.room_id)?.membership === "join";
              return (
                <li key={room.room_id} className="directory-row" data-testid="directory-room" data-room-id={room.room_id}>
                  <span className={`avatar avatar-sm tint-${tintIndex(room.room_id)}`} aria-hidden="true">
                    {initialOf(name)}
                  </span>
                  <span className="directory-text">
                    <span className="member-name">{name}</span>
                    <span className="member-id">
                      {room.num_joined_members} {room.num_joined_members === 1 ? "member" : "members"}
                      {room.topic ? ` · ${room.topic}` : ""}
                    </span>
                  </span>
                  {joined ? (
                    <button type="button" className="button button-small button-quiet" onClick={() => onJoined(room.room_id)} data-testid="directory-open">
                      Open
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="button button-small button-primary"
                      disabled={joining !== null}
                      aria-busy={joining === room.room_id}
                      aria-label={`Join ${name}`}
                      data-testid="directory-join"
                      onClick={async () => {
                        setJoining(room.room_id);
                        setJoinError(undefined);
                        try {
                          onJoined(await client.joinRoom(room.room_id));
                        } catch (e) {
                          setJoinError(describeError(e));
                        } finally {
                          setJoining(null);
                        }
                      }}
                    >
                      {joining === room.room_id ? "Joining…" : "Join"}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {joinError && (
          <p className="field-error" role="alert">
            {joinError}
          </p>
        )}
        {next && (
          <button type="button" className="link-button" onClick={() => void more()} data-testid="directory-more">
            Show more rooms
          </button>
        )}
      </div>
    </section>
  );
}

/** User-directory suggestions as the person types a name or ID. */
export function UserSuggestions({ term, onPick }: { term: string; onPick: (userId: string) => void }) {
  const client = useClient();
  const [results, setResults] = useState<{ user_id: string; display_name?: string }[]>([]);
  const [error, setError] = useState<string | undefined>(undefined);
  const query = term.trim().replace(/^@/, "");

  useEffect(() => {
    if (query.length < 2) {
      setResults([]);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      client
        .searchUsers(query)
        .then((r) => {
          if (!cancelled) {
            setResults(r.results.filter((u) => u.user_id !== client.userId));
            setError(undefined);
          }
        })
        .catch((e) => !cancelled && setError(describeError(e)));
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [client, query]);

  if (error) return <p className="field-hint">User search is unavailable: {error}</p>;
  if (results.length === 0) return null;
  return (
    <ul className="suggestions" aria-label="Matching people" data-testid="user-suggestions">
      {results.map((u) => (
        <li key={u.user_id}>
          <button type="button" className="suggestion" onClick={() => onPick(u.user_id)} data-testid="user-suggestion" data-user-id={u.user_id}>
            <span className={`avatar avatar-sm tint-${tintIndex(u.user_id)}`} aria-hidden="true">
              {initialOf(u.display_name || u.user_id)}
            </span>
            <span className="directory-text">
              <span className="member-name">{u.display_name || u.user_id}</span>
              {u.display_name && <span className="member-id">{u.user_id}</span>}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}
