import { test, expect, type Page } from '@playwright/test';
import { PENDING_SSO_KEY } from '../src/lib/session';
import { assertAccessibleShell } from './support/accessibility';

test('session persistence and bound SSO returns', async ({ browser }, testInfo) => {
	const hs = process.env.CONDUIT_TEST_HS;
	if (!hs) throw new Error('Set CONDUIT_TEST_HS to a local, migrated Conduit server with registration enabled.');
	const base = String(testInfo.project.use.baseURL);
	const url = `${base}/?${new URLSearchParams({ hs })}`;
	const username = `svelte_${crypto.randomUUID().replaceAll('-', '').slice(0, 12)}`;
	const password = `Session-proof-${crypto.randomUUID()}`;
	const context = await browser.newContext();
	const page = await context.newPage();
	const calls: { method: string; path: string; navigation: number }[] = [];
	// A signed-in sync can leave the previous document while goto() commits.
	// Count only requests from the document that actually loaded.
	let navigation = 0;
	page.on('framenavigated', (frame) => { if (frame === page.mainFrame()) navigation += 1; });
	page.on('request', (request) => {
		if (request.url().startsWith(hs)) calls.push({ method: request.method(), path: new URL(request.url()).pathname, navigation });
});
async function api(path: string, accessToken: string, body: unknown, method = 'POST') {
	return fetch(`${hs}${path}`, { method, headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
async function pending(homeserver: string) {
	await page.evaluate(({ key, homeserver }) => sessionStorage.setItem(key, JSON.stringify({ homeserver })), { key: PENDING_SSO_KEY, homeserver });
}
async function signedOut() {
	await expect(page.getByRole('button', { name: 'Sign in with password', exact: true })).toBeVisible();
	await expect(page.getByLabel('Username', { exact: true })).toBeEnabled();
}
async function signedIn() { await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible(); }
try {
	await page.goto(url);
	await signedOut();
	await expect(page.getByRole('button', { name: 'Continue with Identikey' })).toHaveCount(0);
	await page.getByRole('button', { name: 'Create an account', exact: true }).click();
	await page.getByLabel('Username', { exact: true }).fill(username);
	await page.getByLabel('Password', { exact: true }).fill(password);
	await page.getByRole('button', { name: 'Create account', exact: true }).click();
	await signedIn();
	await assertAccessibleShell(page, testInfo);
	const session = await page.evaluate(() => JSON.parse(localStorage.getItem('conduit:web:session')!));
	const profile = await api(`/_matrix/client/v3/profile/${encodeURIComponent(session.userId)}/displayname`, session.accessToken, { displayname: 'Svelte Session Proof' }, 'PUT');
	expect(profile.ok).toBe(true);
	await page.reload();
	await expect(page.getByTestId('profile-display-name')).toHaveText('Svelte Session Proof');
	await page.getByRole('button', { name: 'Sign out', exact: true }).click();
	await signedOut();
	expect(await page.evaluate(() => localStorage.getItem('conduit:web:session'))).toBeNull();
	await page.reload();
	await signedOut();
	await page.getByLabel('Username', { exact: true }).fill(username);
	await page.getByLabel('Password', { exact: true }).fill(password);
	await page.getByRole('button', { name: 'Sign in with password', exact: true }).click();
	await signedIn();
	const loggedIn = await page.evaluate(() => JSON.parse(localStorage.getItem('conduit:web:session')!));

	// Mint a real token without calling the hosted OIDC provider.
	const challenge = await (await api('/_matrix/client/v1/login/get_token', loggedIn.accessToken, {})).json();
	const issued = await api('/_matrix/client/v1/login/get_token', loggedIn.accessToken, {
		auth: { type: 'm.login.password', session: challenge.session, identifier: { type: 'm.id.user', user: username }, password }
	});
	expect(issued.ok).toBe(true);
	const { login_token: loginToken } = await issued.json();
	// Leave the issuing server session alive while testing its login token.
	await page.evaluate(() => localStorage.removeItem('conduit:web:session'));
	await pending(hs);
	const returnUrl = `${url}&${new URLSearchParams({ loginToken })}`;
	const before = calls.length;
	await page.goto(returnUrl);
	await signedIn();
	expect(new URL(page.url()).searchParams.has('loginToken')).toBe(false);
	expect(await page.evaluate(key => sessionStorage.getItem(key), PENDING_SSO_KEY)).toBeNull();
	expect(calls.slice(before).filter((call) => call.method === 'POST' && call.path.endsWith('/login'))).toHaveLength(1);
	// Replay without a new pending record must not call any homeserver endpoint.
	const replayNav = navigation;
	await page.goto(returnUrl);
	await expect(page.getByRole('alert')).toContainText('This tab did not request');
	expect(calls.filter((call) => call.navigation > replayNav)).toHaveLength(0);
	expect(new URL(page.url()).searchParams.has('loginToken')).toBe(false);
	// The same spent token with fresh tab intent gets one failed exchange and a retry.
	await pending(hs);
	await page.goto(returnUrl);
	await expect(page.getByRole('alert')).toContainText('Try again');
	await signedOut();
	for (const mismatch of [true, false]) {
		await pending(mismatch ? 'http://different.invalid' : hs);
		const mark = calls.length;
		await page.goto(mismatch ? returnUrl : `${base}/?loginToken=unsolicited`);
		await expect(page.getByRole('alert')).toContainText('This tab did not request');
		expect(calls.slice(mark)).toHaveLength(0);
		expect(new URL(page.url()).searchParams.has('loginToken')).toBe(false);
	}

	// Advertised SSO changes action priority and binds the outbound callback.
	await page.route(`${hs}/_matrix/client/v3/login`, async (route) => {
		if (route.request().method() === 'GET') await route.fulfill({ json: { flows: [{ type: 'm.login.sso' }] } });
		else await route.continue();
	});
	await page.goto(url);
	await expect(page.getByRole('button', { name: 'Continue with Identikey' })).toBeVisible();
	await expect(page.getByLabel('Password', { exact: true })).toBeVisible();
	await page.route(`${hs}/_matrix/client/v3/login/sso/redirect?**`, (route) => route.fulfill({ contentType: 'text/html', body: 'SSO redirect captured' }));
	await page.getByRole('button', { name: 'Continue with Identikey' }).click();
	await page.waitForURL(`${hs}/_matrix/client/v3/login/sso/redirect?**`);
	const callback = new URL(new URL(page.url()).searchParams.get('redirectUrl')!);
	expect(callback.searchParams.get('hs')).toBe(hs.replace(/\/+$/, ''));
	await page.goto(url);
	expect(await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key)!).homeserver, PENDING_SSO_KEY)).toBe(hs.replace(/\/+$/, ''));
	console.log('PASS: password registration/login, profile, logout persistence, bound SSO, replay, unsolicited/mismatched/missing-hs return guards');
} finally {
	await context.close();
}

});

test('a fresh tab strips the same loginToken URL without sending a login request', async ({ browser, request }, testInfo) => {
	const hs = process.env.CONDUIT_TEST_HS!;
	const username = `unrequested_${crypto.randomUUID().replaceAll('-', '').slice(0, 12)}`;
	const password = `Session-proof-${crypto.randomUUID()}`;
	const credentials = { username, password };
	const challenge = await request.post(`${hs}/_matrix/client/v3/register`, { data: credentials });
	expect(challenge.status()).toBe(401);
	const registration = await request.post(`${hs}/_matrix/client/v3/register`, {
		data: { ...credentials, auth: { type: 'm.login.dummy', session: (await challenge.json()).session } }
	});
	expect(registration.ok()).toBe(true);
	const session = await registration.json();
	const headers = { Authorization: `Bearer ${session.access_token}` };
	const tokenChallenge = await request.post(`${hs}/_matrix/client/v1/login/get_token`, { headers, data: {} });
	expect(tokenChallenge.status()).toBe(401);
	const issued = await request.post(`${hs}/_matrix/client/v1/login/get_token`, {
		headers, data: { auth: {
			type: 'm.login.password', session: (await tokenChallenge.json()).session,
			identifier: { type: 'm.id.user', user: username }, password
		} }
	});
	expect(issued.ok()).toBe(true);
	const { login_token: loginToken } = await issued.json();
	const returnUrl = `${testInfo.project.use.baseURL}/?${new URLSearchParams({ hs, loginToken })}`;
	const context = await browser.newContext();
	try {
		const page = await context.newPage();
		const requests: string[] = [];
		page.on('request', req => { if (req.url().startsWith(hs)) requests.push(req.url()); });
		// No prior navigation and no addInitScript: this tab has no SSO intent.
		await page.goto(returnUrl);
		await expect(page.getByRole('alert')).toContainText('This tab did not request');
		await expect(page.getByRole('button', { name: 'Sign in with password', exact: true })).toBeVisible();
		expect(new URL(page.url()).searchParams.has('loginToken')).toBe(false);
		expect(await page.evaluate(key => sessionStorage.getItem(key), PENDING_SSO_KEY)).toBeNull();
		expect(requests).toEqual([]);

		// Revisit precisely that URL with tab intent. Its successful exchange also
		// proves the no-record visit did not spend the still-valid server token.
		await page.evaluate(({ key, homeserver }) => {
			sessionStorage.setItem(key, JSON.stringify({ homeserver }));
		}, { key: PENDING_SSO_KEY, homeserver: hs });
		await page.goto(returnUrl);
		await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
		expect(new URL(page.url()).searchParams.has('loginToken')).toBe(false);
		expect(requests.filter(url => new URL(url).pathname.endsWith('/login'))).toHaveLength(1);
	} finally { await context.close(); }
});
