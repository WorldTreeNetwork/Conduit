import { expect, type Page } from '@playwright/test';

export type Account = {
	homeserverUrl: string;
	userId: string;
	accessToken: string;
	deviceId: string;
	refreshToken?: string;
};

/** Register through the homeserver. The signed-out page has no password form. */
export async function registerAccount(hs: string, username: string, password: string): Promise<Account> {
	const homeserverUrl = hs.replace(/\/+$/, '');
	const challenge = await fetch(`${homeserverUrl}/_matrix/client/v3/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ username, password }),
	});
	expect(challenge.status).toBe(401);
	const registration = await fetch(`${homeserverUrl}/_matrix/client/v3/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			username,
			password,
			auth: { type: 'm.login.dummy', session: (await challenge.json()).session },
		}),
	});
	expect(registration.ok, `register ${registration.status}`).toBe(true);
	const body = await registration.json();
	return {
		homeserverUrl,
		userId: body.user_id,
		accessToken: body.access_token,
		deviceId: body.device_id,
		...(typeof body.refresh_token === 'string' ? { refreshToken: body.refresh_token } : {}),
	};
}

/** Sign in through the homeserver. The signed-out page has no password form. */
export async function loginAccount(hs: string, username: string, password: string): Promise<Account> {
	const homeserverUrl = hs.replace(/\/+$/, '');
	const response = await fetch(`${homeserverUrl}/_matrix/client/v3/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			type: 'm.login.password',
			identifier: { type: 'm.id.user', user: username },
			password,
			refresh_token: true,
		}),
	});
	expect(response.ok, `login ${response.status}`).toBe(true);
	const body = await response.json();
	return {
		homeserverUrl,
		userId: body.user_id,
		accessToken: body.access_token,
		deviceId: body.device_id,
		...(typeof body.refresh_token === 'string' ? { refreshToken: body.refresh_token } : {}),
	};
}

/** Open the shell from a session the page did not collect. */
export async function enterSession(page: Page, account: Account) {
	await page.evaluate((session) => {
		localStorage.setItem('conduit:web:session', JSON.stringify(session));
	}, account);
	await page.reload();
	await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
}
