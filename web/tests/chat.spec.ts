import { test, expect, type Page } from '@playwright/test';
import { assertAccessibleShell } from './support/accessibility';

test('two people exchange messages and recover failed sends', async ({ browser }, testInfo) => {
	const hs = process.env.CONDUIT_TEST_HS;
	if (!hs) throw new Error('Set CONDUIT_TEST_HS to a migrated homeserver with registration enabled.');
	const base = String(testInfo.project.use.baseURL);
	const url = `${base}/?${new URLSearchParams({ hs })}`;
	const aliceContext = await browser.newContext();
	const bobContext = await browser.newContext();
	const alice = await aliceContext.newPage();
	const bob = await bobContext.newPage();
	const errors: string[] = [];
	for (const page of [alice, bob]) page.on('pageerror', error => errors.push(error.message));
	const run = crypto.randomUUID().replaceAll('-', '').slice(0, 12);
	const roomName = `Conversation ${run}`;
	const password = `Chat-proof-${crypto.randomUUID()}`;

	type Session = { accessToken: string; userId: string };
	async function signup(page: Page, name: string): Promise<Session> {
	 await page.goto(url);
	 await page.getByRole('button', { name: 'Create an account', exact: true }).click();
	 await page.getByLabel('Username', { exact: true }).fill(name);
	 await page.getByLabel('Password', { exact: true }).fill(password);
	 await page.getByRole('button', { name: 'Create account', exact: true }).click();
	 await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
	 return page.evaluate(() => JSON.parse(localStorage.getItem('conduit:web:session')!));
	}
	async function api(session: Session, path: string, body: unknown) {
	 const response = await fetch(`${hs}/_matrix/client/v3${path}`, {
	  method: 'POST', headers: { Authorization: `Bearer ${session.accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body)
	 });
	 expect(response.ok, `${path}: ${response.status}`).toBe(true);
	 return response.json();
	}
	async function message(page: Page, body: string) {
	 await page.getByRole('textbox', { name: `Message ${roomName}`, exact: true }).fill(body);
	 await page.getByRole('button', { name: 'Send', exact: true }).click();
	}
	const log = (page: Page) => page.getByRole('log', { name: 'Messages', exact: true });
	try {
	 const a = await signup(alice, `chat_a_${run}`);
	 const b = await signup(bob, `chat_b_${run}`);
	 await alice.getByRole('button', { name: 'Create room', exact: true }).first().click();
	 await alice.getByLabel('Room name', { exact: true }).fill(roomName);
	 await alice.getByRole('dialog').getByRole('button', { name: 'Create room', exact: true }).click();
	 await expect(alice.getByRole('heading', { name: roomName, exact: true })).toBeVisible();
	 const roomHash = new URL(alice.url()).hash;
	 const roomId = decodeURIComponent(roomHash.replace('#/room/', ''));
	 await alice.getByRole('button', { name: 'Invite', exact: true }).click();
	 await alice.getByLabel('Matrix user ID', { exact: true }).fill(b.userId);
	 await alice.getByRole('button', { name: 'Send invitation', exact: true }).click();
	 await expect(alice.getByRole('dialog')).toHaveCount(0);
	 await bob.getByRole('button', { name: 'Accept invitation', exact: true }).click();
	 await expect(bob.getByRole('heading', { name: roomName, exact: true })).toBeVisible();

	 // Hold the PUT to prove local echo precedes server acceptance.
	 let release!: () => void;
	 const held = new Promise<void>(resolve => { release = resolve; });
	 await alice.route('**/send/m.room.message/**', async route => { await held; await route.continue(); }, { times: 1 });
	 await message(alice, 'Hello from Alice');
	 try {
	  await expect(log(alice).locator('[data-txn-id]').filter({ hasText: 'Hello from Alice' })).toBeVisible();
	  await expect(log(bob).getByText('Hello from Alice', { exact: true })).toHaveCount(0);
	 } finally { release(); }
	 await expect(log(bob).getByText('Hello from Alice', { exact: true })).toBeVisible();
	 await expect(log(alice).getByText('Hello from Alice', { exact: true })).toHaveCount(1);
	 await message(bob, 'Hello from Bob');
	 await expect(log(alice).getByText('Hello from Bob', { exact: true })).toBeVisible();

	 await assertAccessibleShell(alice, testInfo);

	 // A permanent response avoids depending on retry backoff timing.
	 let fail = true;
	 const transactions: string[] = [];
	 await alice.route('**/send/m.room.message/**', async route => {
	  transactions.push(route.request().url());
	  if (fail) await route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ errcode: 'M_FORBIDDEN', error: 'Injected send failure' }) });
	  else await route.continue();
	 });
	 await message(alice, 'Retry this message');
	 await expect(log(alice).getByText('Not sent', { exact: true })).toBeVisible();
	 await expect(log(bob).getByText('Retry this message', { exact: true })).toHaveCount(0);
	 fail = false;
	 await log(alice).getByRole('button', { name: 'Retry', exact: true }).click();
	 await expect(log(bob).getByText('Retry this message', { exact: true })).toBeVisible();
	 await expect(log(alice).getByText('Retry this message', { exact: true })).toHaveCount(1);
	 expect(transactions.length).toBe(2);
	 expect(transactions[0]).toBe(transactions[1]);
	 await alice.unroute('**/send/m.room.message/**');

	 await bob.getByRole('link', { name: 'Conduit', exact: true }).click();
	 await message(alice, 'An unread preview');
	 const roomLink = bob.getByRole('navigation', { name: 'Joined rooms' }).getByRole('link').filter({ hasText: roomName });
	 await expect(roomLink).toContainText('An unread preview');
	 await expect(roomLink.locator('[aria-label$=" unread"]')).toBeVisible();
	 await roomLink.click();

	 // Send enough events to require back pagination on a fresh session cache.
	 for (let i = 0; i < 36; i++) {
	  const response = await fetch(`${hs}/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/history_${run}_${i}`, {
	   method: 'PUT', headers: { Authorization: `Bearer ${a.accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ msgtype: 'm.text', body: `History ${i}` })
	  });
	  expect(response.ok).toBe(true);
	 }
	 await expect(log(alice).getByText('History 35', { exact: true })).toBeVisible();
	 await alice.addInitScript(() => localStorage.removeItem('conduit:web:sync'));
	 await alice.reload();
	 await expect(log(alice).getByText('History 35', { exact: true })).toBeVisible();
	 await expect(log(alice).getByText('Hello from Alice', { exact: true })).toHaveCount(0);
	 await alice.getByRole('button', { name: 'Load older messages', exact: true }).click();
	 await expect(log(alice).getByText('Hello from Alice', { exact: true })).toBeVisible();

	 // Joining uses its own dialog.
	 const publicRoom = await api(a, '/createRoom', { name: `Public ${run}`, preset: 'public_chat', visibility: 'public' }) as { room_id: string };
	 await bob.getByRole('button', { name: 'Join room', exact: true }).first().click();
	 await bob.getByLabel('Room ID or alias', { exact: true }).fill(publicRoom.room_id);
	 await bob.getByRole('dialog').getByRole('button', { name: 'Join room', exact: true }).click();
	 await expect(bob.getByRole('heading', { name: `Public ${run}`, exact: true })).toBeVisible();

	 await api(b, `/rooms/${encodeURIComponent(roomId)}/leave`, {});
	 await expect(bob.getByRole('navigation', { name: 'Joined rooms' }).getByRole('link').filter({ hasText: roomName })).toHaveCount(0);
	 await bob.goto(`${url}${roomHash}`);
	 await expect.poll(() => new URL(bob.url()).hash).toBe('#/');
	 await expect(bob.getByRole('heading', { name: 'A place to catch up.', exact: true })).toBeVisible();

	 // Mobile opens a room and provides a route back to the rail.
	 await alice.setViewportSize({ width: 390, height: 844 });
	 await expect(alice.getByRole('textbox', { name: `Message ${roomName}`, exact: true })).toBeVisible();
	 await expect(alice.getByRole('button', { name: 'Send', exact: true })).toBeVisible();
	 expect(await alice.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
	 await alice.getByRole('link', { name: '← Rooms', exact: true }).click();
	 await expect(alice.getByRole('navigation', { name: 'Joined rooms' })).toBeVisible();
	 expect(errors).toEqual([]);
	 console.log('PASS: create, invite, accept, two-way send, local echo, retry, previews, unread, history, join, left-room hash, mobile navigation');
	} finally { await aliceContext.close(); await bobContext.close(); }

});
