// Run with Bun; uses the existing React proof's Playwright installation until
// the Svelte browser-proof node establishes its own harness.
import { chromium, expect } from '../../client/node_modules/@playwright/test/index.mjs';
import { PENDING_SSO_KEY } from '../src/lib/session';

const hs = process.env.CONDUIT_TEST_HS;
if (!hs) throw new Error('Set CONDUIT_TEST_HS to a local, migrated Conduit server with registration enabled.');
const base = process.env.WEB_BASE_URL ?? 'http://localhost:5173';
const url = `${base}/?${new URLSearchParams({ hs })}`;
const username = `svelte_${Date.now().toString(36)}`;
const password = `Session-proof-${crypto.randomUUID()}`;
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const calls: { method: string; path: string }[] = [];
page.on('request', (request) => {
	if (request.url().startsWith(hs)) calls.push({ method: request.method(), path: new URL(request.url()).pathname });
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
	expect(calls.slice(before).filter((call) => call.method === 'POST' && call.path.endsWith('/login'))).toHaveLength(1);
	// Replay without a new pending record must not call any homeserver endpoint.
	const replay = calls.length;
	await page.goto(returnUrl);
	await expect(page.getByRole('alert')).toContainText('This tab did not request');
	expect(calls.slice(replay)).toHaveLength(0);
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
	await browser.close();
}
