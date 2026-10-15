import { test, expect, type Page } from '@playwright/test';
import { enterSession, registerAccount } from './support/account';

test('settings, media, people, directory, threads and reconnect', async ({ browser }, testInfo) => {
	const hs = process.env.CONDUIT_TEST_HS;
	if (!hs) throw new Error('Set CONDUIT_TEST_HS to a migrated homeserver with registration enabled.');
	const base = String(testInfo.project.use.baseURL);
	const url = `${base}/?${new URLSearchParams({ hs })}`;
	const aContext = await browser.newContext();
	const bContext = await browser.newContext();
	const alice = await aContext.newPage(), bob = await bContext.newPage();
	const errors: string[] = [];
	for (const page of [alice, bob]) page.on('pageerror', e => errors.push(e.message));
	const run = crypto.randomUUID().replaceAll('-', '').slice(0, 12);
	const password = `Rest-proof-${crypto.randomUUID()}`;
	const roomName = `Remaining surfaces ${run}`;
	const log = (page: Page) => page.getByRole('log', { name: 'Messages', exact: true });
	const dialog = (page: Page) => page.getByRole('dialog');
	type Session = { accessToken: string; userId: string; deviceId: string };
	async function signup(page: Page, name: string): Promise<Session> {
	 await page.goto(url);
	 const account = await registerAccount(hs, name, password);
	 await enterSession(page, account);
	 await expect(page.getByTestId('sync-status')).toHaveAttribute('data-state', 'live');
	 return { accessToken: account.accessToken, userId: account.userId, deviceId: account.deviceId };
	}
	async function api(session: Session, method: string, path: string, body?: unknown) {
	 const response = await fetch(`${hs}/_matrix/client/v3${path}`, {
	  method, headers: { Authorization: `Bearer ${session.accessToken}`, 'Content-Type': 'application/json' },
	  ...(body === undefined ? {} : { body: JSON.stringify(body) })
	 });
	 expect(response.ok, `${method} ${path}: ${response.status}`).toBe(true);
	 return response.json();
	}
	async function send(page: Page, body: string, name = roomName) {
	 await page.getByRole('textbox', { name: `Message ${name}`, exact: true }).fill(body);
	 await page.getByRole('button', { name: 'Send', exact: true }).click();
	}
	async function close(page: Page) { await dialog(page).getByRole('button', { name: 'Close', exact: true }).click(); await expect(dialog(page)).toHaveCount(0); }
	try {
	 const a = await signup(alice, `rest_a_${run}`), b = await signup(bob, `rest_b_${run}`);
	 await alice.getByRole('link', { name: 'Settings', exact: true }).click();
	 await expect(alice.getByRole('heading', { name: 'Password', exact: true })).toHaveCount(0);
	 await expect(alice.getByRole('button', { name: 'Deactivate account', exact: true })).toHaveCount(0);
	 await expect(alice.getByLabel('Password')).toHaveCount(0);
	 await alice.getByLabel('Display name', { exact: true }).fill('Alice of Conduit');
	 await alice.getByRole('button', { name: 'Save', exact: true }).click();
	 await expect(alice.getByTestId('displayname-status')).toHaveText('Display name saved.');
	 expect((await api(a, 'GET', `/profile/${encodeURIComponent(a.userId)}`)).displayname).toBe('Alice of Conduit');
	 await expect(alice.getByTestId('profile-display-name')).toHaveText('Alice of Conduit');
	 await alice.getByRole('radio', { name: 'Night', exact: true }).check();
	 await expect(alice.locator('html')).toHaveAttribute('data-theme', 'dark');
	 await alice.reload();
	 await expect(alice.locator('html')).toHaveAttribute('data-theme', 'dark');
	 await expect(alice.getByLabel('Display name', { exact: true })).toHaveValue('Alice of Conduit');
	 await alice.getByRole('radio', { name: 'Match system', exact: true }).check();
	 // Rename the current device through the account controls and verify the server result.
	 const device = alice.getByTestId('device-row').filter({ hasText: a.deviceId });
	 await device.getByRole('button', { name: /^Rename / }).click();
	 await device.getByLabel('New device name', { exact: true }).fill('My Svelte browser');
	 await device.getByRole('button', { name: 'Save device name', exact: true }).click();
	 await expect(device).toContainText('My Svelte browser');
	 expect((await api(a, 'GET', `/devices/${encodeURIComponent(a.deviceId)}`)).display_name).toBe('My Svelte browser');
	 await alice.getByRole('link', { name: '← All rooms', exact: true }).click();

	 await alice.getByRole('button', { name: 'Create room', exact: true }).first().click();
	 await alice.getByLabel('Room name', { exact: true }).fill(roomName);
	 await dialog(alice).getByRole('button', { name: 'Create room', exact: true }).click();
	 await expect(alice.getByRole('heading', { name: roomName, exact: true })).toBeVisible();
	 const roomId = decodeURIComponent(new URL(alice.url()).hash.replace('#/room/', ''));
	 await alice.getByRole('button', { name: 'Invite', exact: true }).click();
	 await alice.getByLabel('Matrix user ID', { exact: true }).fill(b.userId);
	 await alice.getByRole('button', { name: 'Send invitation', exact: true }).click();
	 await bob.getByRole('button', { name: 'Accept invitation', exact: true }).click();
	 await expect(bob.getByRole('heading', { name: roomName, exact: true })).toBeVisible();
	 await send(alice, 'A thread starts here');
	 await expect(log(bob).getByText('A thread starts here', { exact: true })).toBeVisible();
	 await alice.getByRole('button', { name: 'People', exact: true }).click();
	 await expect(dialog(alice).getByTestId('joined-members').getByTestId('member-row')).toHaveCount(2);
	 await expect(dialog(alice)).toContainText('Alice of Conduit');
	 // Presence comes from a real /sync response, not an injected UI state.
	 await api(b, 'PUT', `/presence/${encodeURIComponent(b.userId)}/status`, { presence: 'unavailable' });
	 await expect(dialog(alice).getByTestId('member-row').filter({ hasText: b.userId }).getByTestId('presence')).toHaveAttribute('data-presence', 'unavailable');
	 await close(alice);

	 const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
	 await alice.getByLabel('Attachment', { exact: true }).setInputFiles({ name: 'dot.png', mimeType: 'image/png', buffer: png });
	 const image = log(bob).getByRole('img', { name: 'dot.png', exact: true });
	 await expect(image).toBeVisible();
	 await expect(image).toHaveAttribute('src', /^blob:/);
	 await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);

	 const root = log(bob).locator('[data-event-id]').filter({ hasText: 'A thread starts here' });
	 await root.getByRole('button', { name: 'Start thread', exact: true }).click();
	 await expect(bob.getByLabel('Reply in thread', { exact: true })).toBeFocused();
	 await bob.getByLabel('Reply in thread', { exact: true }).fill('A threaded reply');
	 await bob.getByRole('button', { name: 'Send reply', exact: true }).click();
	 await expect(dialog(bob).getByText('A threaded reply', { exact: true })).toHaveCount(1);
	 const aliceRoot = log(alice).locator('[data-event-id]').filter({ hasText: 'A thread starts here' });
	 await aliceRoot.getByRole('button', { name: 'Open thread, 1 replies', exact: true }).click();
	 await expect(dialog(alice).getByText('A threaded reply', { exact: true })).toBeVisible();
	 // A failed thread send stays in the thread and retains its transaction on retry.
	 let fail = true;
	 const transactions: string[] = [];
	 await alice.route('**/send/m.room.message/**', async route => {
	  transactions.push(route.request().url());
	  if (fail) await route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ errcode: 'M_FORBIDDEN', error: 'Injected failure' }) });
	  else await route.continue();
	 });
	 await alice.getByLabel('Reply in thread', { exact: true }).fill('Retry in thread');
	 await alice.getByRole('button', { name: 'Send reply', exact: true }).click();
	 await expect(dialog(alice).getByText('Not sent', { exact: true })).toBeVisible();
	 fail = false;
	 await dialog(alice).getByRole('button', { name: 'Retry', exact: true }).click();
	 await expect(dialog(bob).getByText('Retry in thread', { exact: true })).toBeVisible();
	 expect(transactions.length).toBe(2); expect(transactions[0]).toBe(transactions[1]);
	 await alice.unroute('**/send/m.room.message/**');
	 await close(alice); await close(bob);
	 await expect(log(alice).getByText('A threaded reply', { exact: true })).toHaveCount(0);

	 await alice.getByRole('button', { name: 'Room settings', exact: true }).click();
	 await dialog(alice).getByLabel('Topic', { exact: true }).fill('A Svelte conversation');
	 await dialog(alice).getByLabel('Who can read history', { exact: true }).selectOption('joined');
	 await dialog(alice).getByRole('button', { name: 'Save changes', exact: true }).click();
	 await expect(dialog(alice).getByRole('status')).toHaveText('Saved.');
	 await close(alice);
	 await expect(bob.getByText('A Svelte conversation', { exact: true })).toBeVisible();

	 const publicName = `Directory ${run}`;
	 const publicRoom = await api(a, 'POST', '/createRoom', { name: publicName, preset: 'public_chat', visibility: 'public' });
	 await bob.getByRole('button', { name: 'Directory', exact: true }).click();
	 await dialog(bob).getByLabel('Search public rooms', { exact: true }).fill(publicName);
	 const entry = dialog(bob).getByTestId('directory-room').filter({ hasText: publicName });
	 await expect(entry).toBeVisible();
	 await entry.getByRole('button', { name: `Join ${publicName}`, exact: true }).click();
	 await expect(bob.getByRole('heading', { name: publicName, exact: true })).toBeVisible();
	 expect(decodeURIComponent(new URL(bob.url()).hash)).toBe(`#/room/${publicRoom.room_id}`);

	 // Fail transport at the /sync boundary, then resume real server sync.
	 await alice.route('**/_matrix/client/v3/sync**', route => route.abort('connectionreset'));
	 await send(alice, 'Wake the sync poll');
	 await expect(alice.getByTestId('connection-banner')).toBeVisible();
	 await expect(alice.getByTestId('sync-status')).toHaveAttribute('data-state', 'reconnecting');
	 await alice.getByTestId('retry-sync').click();
	 await expect(alice.getByTestId('connection-banner')).toBeVisible();
	 await alice.unroute('**/_matrix/client/v3/sync**');
	 await alice.getByTestId('retry-sync').click();
	 await expect(alice.getByTestId('sync-status')).toHaveAttribute('data-state', 'live');
	 await expect(alice.getByTestId('connection-banner')).toHaveCount(0);
	 await expect(log(alice).getByText('Wake the sync poll', { exact: true })).toBeVisible();

	 await alice.setViewportSize({ width: 390, height: 844 });
	 await alice.getByRole('button', { name: 'People', exact: true }).click();
	 await expect(dialog(alice).getByTestId('joined-members')).toBeVisible();
	 expect(await alice.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
	 await close(alice);
	 await alice.getByRole('link', { name: '← Rooms', exact: true }).click();
	 await alice.getByRole('link', { name: 'Settings', exact: true }).click();
	 await expect(alice.getByLabel('Display name', { exact: true })).toBeVisible();
	 expect(await alice.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
	 expect(errors).toEqual([]);
	 console.log('PASS: profile and persistence, theme, device rename, image preview, members, presence, directory join, threads and retry, room settings, reconnect and sync recovery, mobile');
	} finally { await aContext.close(); await bContext.close(); }

});
