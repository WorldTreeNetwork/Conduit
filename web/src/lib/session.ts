// The Svelte app's session boundary. Matrix operations stay in the shared core.
import {
	HttpClient, realClock, getLoginFlows, loginWithPassword, register,
	MatrixClient, LocalStorageStore, loadStoredSession, saveSession, clearStoredSession,
	type Session
} from '../../../client/src/core/index';
import { homeserverProblem } from './homeserver.js';

export { describeError, validateUsername } from '../../../client/src/core/index';
export type { MatrixClient, Session } from '../../../client/src/core/index';
export const PENDING_SSO_KEY = 'conduit:pending-sso';
export const sessionStore = new LocalStorageStore('conduit:web:');

export type SsoReturn =
	| { state: 'none' }
	| { state: 'rejected' }
	| { state: 'ready'; homeserver: string; token: string };

type ReturnBrowser = Pick<Window, 'location' | 'history' | 'sessionStorage'>;

/** Synchronous: called during page initialization, before any UI renders or request starts. */
export function consumeSsoReturn(browser: ReturnBrowser): SsoReturn {
	const url = new URL(browser.location.href);
	if (!url.searchParams.has('loginToken')) return { state: 'none' };
	const token = url.searchParams.get('loginToken');
	const homeserver = url.searchParams.get('hs');
	url.searchParams.delete('loginToken');
	browser.history.replaceState(browser.history.state, '', url.toString());

	// Consume the tab's intent even on rejection, and always before exchanging the token.
	let pending: unknown;
	try {
		const raw = browser.sessionStorage.getItem(PENDING_SSO_KEY);
		browser.sessionStorage.removeItem(PENDING_SSO_KEY);
		pending = raw ? JSON.parse(raw) : null;
	} catch {
		return { state: 'rejected' };
	}
	if (!token || !homeserver || homeserverProblem(homeserver) ||
		!pending || typeof pending !== 'object' ||
		!('homeserver' in pending) || pending.homeserver !== homeserver) {
		return { state: 'rejected' };
	}
	return { state: 'ready', homeserver, token };
}

export function beginSso(homeserver: string, browser: ReturnBrowser): void {
	const hs = homeserver.trim().replace(/\/+$/, '');
	if (homeserverProblem(hs)) throw new Error('Enter a valid homeserver address.');
	const redirect = new URL(browser.location.href);
	redirect.searchParams.delete('loginToken');
	redirect.searchParams.set('hs', hs);
	// If sessionStorage is unavailable, fail here rather than leave for an unbound return.
	browser.sessionStorage.setItem(PENDING_SSO_KEY, JSON.stringify({ homeserver: hs }));
	browser.location.assign(`${hs}/_matrix/client/v3/login/sso/redirect?${new URLSearchParams({ redirectUrl: redirect.toString() })}`);
}

export function sessionHttp(homeserver: string): HttpClient {
	return new HttpClient({ baseUrl: homeserver.trim(), clock: realClock });
}

export async function offersSso(homeserver: string): Promise<boolean> {
	return (await getLoginFlows(sessionHttp(homeserver))).some((flow) => flow.type === 'm.login.sso');
}

export async function passwordSession(homeserver: string, username: string, password: string, signup: boolean): Promise<Session> {
	const http = sessionHttp(homeserver);
	return signup ? register(http, username, password) : loginWithPassword(http, username, password);
}

export async function exchangeSso(result: Extract<SsoReturn, { state: 'ready' }>): Promise<Session> {
	const http = sessionHttp(result.homeserver);
	const body = await http.request<{
		user_id: string; access_token: string; device_id: string;
		refresh_token?: string; expires_in_ms?: number;
	}>('POST', '/_matrix/client/v3/login', {
		auth: false,
		maxRetries: 0, // Single-use credentials must never be retried, even after a network failure.
		body: { type: 'm.login.token', token: result.token, initial_device_display_name: 'Conduit web', refresh_token: true }
	});
	if (!body.user_id || !body.access_token || !body.device_id) throw new Error('The server did not return a usable session.');
	return {
		homeserverUrl: http.baseUrl, userId: body.user_id, accessToken: body.access_token,
		deviceId: body.device_id, refreshToken: body.refresh_token,
		expiresAt: typeof body.expires_in_ms === 'number' ? Date.now() + body.expires_in_ms : undefined
	};
}

export function restoreSession(homeserver: string): Session | undefined {
	const stored = loadStoredSession(sessionStore);
	return stored?.homeserverUrl === homeserver.trim().replace(/\/+$/, '') ? stored : undefined;
}

export function openSession(session: Session): MatrixClient {
	saveSession(sessionStore, session);
	return new MatrixClient({ session, store: sessionStore });
}

export function clearSession(): void {
	clearStoredSession(sessionStore);
}
