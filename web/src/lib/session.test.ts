/// <reference types="bun" />
import { afterEach, describe, expect, test } from 'bun:test';
import { beginSso, consumeSsoReturn, exchangeSso, offersSso, PENDING_SSO_KEY } from './session.js';

function browser(search: string, pending?: string) {
	const values = new Map(pending === undefined ? [] : [[PENDING_SSO_KEY, pending]]);
	const history = {
		state: { preserved: true },
		replaceState(state: unknown, _unused: string, url?: string | URL | null) {
			expect(state).toEqual({ preserved: true });
			location.href = String(url);
		}
	};
	const location = { href: `https://client.example/?${search}#room`, assign(url: string) { this.href = url; } };
	const sessionStorage = {
		getItem: (key: string) => values.get(key) ?? null,
		setItem: (key: string, value: string) => { values.set(key, value); },
		removeItem: (key: string) => { values.delete(key); }
	};
	return { history, location, sessionStorage } as unknown as Pick<Window, 'history' | 'location' | 'sessionStorage'>;
}

const hs = 'https://matrix.example';
const pending = JSON.stringify({ homeserver: hs });
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

describe('SSO return admission', () => {
	for (const [name, query, record] of [
		['no pending record', `hs=${hs}&loginToken=secret`, undefined],
		['different homeserver', 'hs=https://other.example&loginToken=secret', pending],
		['missing hs', 'loginToken=secret', pending],
		['empty hs', 'hs=&loginToken=secret', pending],
		['malformed record', `hs=${hs}&loginToken=secret`, '{'],
		['empty token', `hs=${hs}&loginToken=`, pending],
		['invalid address', 'hs=javascript:bad&loginToken=secret', JSON.stringify({ homeserver: 'javascript:bad' })]
	] as const) {
		test(name, () => {
			const tab = browser(query, record);
			expect(consumeSsoReturn(tab)).toEqual({ state: 'rejected' });
			expect(tab.location.href).not.toContain('loginToken');
			expect(tab.location.href).toEndWith('#room');
			expect(tab.sessionStorage.getItem(PENDING_SSO_KEY)).toBeNull();
		});
	}

	test('matching return removes URL token and pending intent synchronously; replay is rejected', () => {
		const tab = browser(`hs=${hs}&loginToken=secret&loginToken=second`, pending);
		expect(consumeSsoReturn(tab)).toEqual({ state: 'ready', homeserver: hs, token: 'secret' });
		expect(tab.location.href).not.toContain('loginToken');
		expect(tab.sessionStorage.getItem(PENDING_SSO_KEY)).toBeNull();
		tab.location.href = `https://client.example/?hs=${hs}&loginToken=secret`;
		expect(consumeSsoReturn(tab)).toEqual({ state: 'rejected' });
	});

	test('outbound redirect writes the same homeserver into tab intent and redirectUrl', () => {
		const tab = browser('keep=1&loginToken=old');
		beginSso(`${hs}/`, tab);
		const target = new URL(tab.location.href);
		const callback = new URL(target.searchParams.get('redirectUrl')!);
		expect(target.origin).toBe(hs);
		expect(target.pathname).toBe('/_matrix/client/v3/login/sso/redirect');
		expect(callback.searchParams.get('hs')).toBe(hs);
		expect(callback.searchParams.get('keep')).toBe('1');
		expect(callback.searchParams.has('loginToken')).toBe(false);
		expect(JSON.parse(tab.sessionStorage.getItem(PENDING_SSO_KEY)!)).toEqual({ homeserver: hs });
	});

	test('a transient exchange failure sends exactly one token login request', async () => {
		let calls = 0;
		globalThis.fetch = (async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
			calls++;
			expect(JSON.parse(init!.body as string).type).toBe('m.login.token');
			return new Response('{}', { status: 503 });
		}) as unknown as typeof fetch;
		await expect(exchangeSso({ state: 'ready', homeserver: hs, token: 'secret' })).rejects.toThrow();
		expect(calls).toBe(1);
	});
});

test('Identikey is enabled only by an advertised m.login.sso flow', async () => {
	for (const [flows, offered] of [
		[[{ type: 'm.login.password' }], false],
		[[{ type: 'm.login.sso' }], true],
		[[], false]
	] as const) {
		globalThis.fetch = (async () => Response.json({ flows })) as unknown as typeof fetch;
		expect(await offersSso(hs)).toBe(offered);
	}
});

test('password registration completes dummy UIA, login restores profile, and logout clears storage', async () => {
	const { passwordSession, openSession, restoreSession, clearSession } = await import('./session.js');
	const storage = new Map<string, string>();
	const previousWindow = globalThis.window;
	globalThis.window = { localStorage: {
		getItem: (key: string) => storage.get(key) ?? null,
		setItem: (key: string, value: string) => { storage.set(key, value); },
		removeItem: (key: string) => { storage.delete(key); }
	} } as unknown as Window & typeof globalThis;
	const requests: string[] = [];
	globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
		const path = new URL(String(input)).pathname;
		requests.push(path);
		const body = init?.body ? JSON.parse(init.body as string) : {};
		if (path.endsWith('/register') && !body.auth) {
			return Response.json({ session: 'uia', flows: [{ stages: ['m.login.dummy'] }] }, { status: 401 });
		}
		if (path.endsWith('/register')) expect(body.auth).toEqual({ type: 'm.login.dummy', session: 'uia' });
		if (path.endsWith('/login')) expect(body).toMatchObject({ type: 'm.login.password', identifier: { type: 'm.id.user', user: 'alice' } });
		if (path.includes('/profile/')) return Response.json({ displayname: 'Alice Example' });
		if (path.endsWith('/logout')) return Response.json({});
		return Response.json({ user_id: '@alice:matrix.example', access_token: 'access', device_id: 'DEVICE' });
	}) as unknown as typeof fetch;
	try {
		const registered = await passwordSession(hs, 'alice', 'password', true);
		expect(registered.userId).toBe('@alice:matrix.example');
		const session = await passwordSession(hs, 'alice', 'password', false);
		const client = openSession(session);
		expect(restoreSession(hs)).toEqual(session);
		expect(await client.getProfile(client.userId)).toEqual({ displayname: 'Alice Example' });
		await client.logout();
		expect(restoreSession(hs)).toBeUndefined();
		expect(storage.size).toBe(0);
		expect(requests.filter((path) => path.endsWith('/register'))).toHaveLength(2);
	} finally {
		clearSession();
		globalThis.window = previousWindow;
	}
});
