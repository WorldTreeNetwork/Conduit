// Homeserver resolution, same order as client/src/config.ts:
// `?hs=<url>` wins (and pins it, hiding the field), then the build's
// VITE_CONDUIT_HOMESERVER, then a localhost default.

export const DEFAULT_HOMESERVER = 'http://localhost:8008';

export interface ResolvedHomeserver {
	url: string;
	/** `?hs=` named the homeserver: the field is hidden. */
	pinned: boolean;
}

export function resolveHomeserver(search: string, env: string | undefined): ResolvedHomeserver {
	const fromQuery = new URLSearchParams(search).get('hs')?.trim();
	if (fromQuery) return { url: fromQuery, pinned: true };
	if (env?.trim()) return { url: env.trim(), pinned: false };
	return { url: DEFAULT_HOMESERVER, pinned: false };
}

export function configuredHomeserver(): ResolvedHomeserver {
	return resolveHomeserver(
		window.location.search,
		import.meta.env.VITE_CONDUIT_HOMESERVER as string | undefined
	);
}

/** Returns an error sentence for the field, or null when the address is usable. */
export function homeserverProblem(url: string): string | null {
	if (!url.trim()) return 'Enter the address of your homeserver, for example http://localhost:8008.';
	try {
		const parsed = new URL(url.trim());
		if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
			return 'Use an http:// or https:// address.';
		}
	} catch {
		return 'That is not a web address. Include http:// or https://.';
	}
	return null;
}

export type Probe =
	| { state: 'ok'; versions: string[] }
	| { state: 'unreachable'; message: string };

/** GET /_matrix/client/versions: the one call a signed-out client can make. */
export async function probeHomeserver(url: string, signal?: AbortSignal): Promise<Probe> {
	const base = url.trim().replace(/\/+$/, '');
	try {
		const res = await fetch(`${base}/_matrix/client/versions`, { signal });
		if (!res.ok) return { state: 'unreachable', message: `The homeserver answered ${res.status}.` };
		const body = (await res.json()) as { versions?: unknown };
		const versions = Array.isArray(body.versions) ? body.versions.map(String) : [];
		if (!versions.length) return { state: 'unreachable', message: 'That server does not speak Matrix.' };
		return { state: 'ok', versions };
	} catch (err) {
		if ((err as Error).name === 'AbortError') throw err;
		return { state: 'unreachable', message: `Cannot reach ${base}.` };
	}
}
