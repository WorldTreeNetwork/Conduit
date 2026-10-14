// Core journeys: two people register in separate browser contexts, create a
// room, invite, accept, chat both ways with unread indicators, and sign out.
import { expect, test } from "@playwright/test";
import {
  apiWhoami,
  awaitIdle,
  createRoomViaUi,
  expectLive,
  message,
  newUserPage,
  openMembers,
  sendViaUi,
} from "./support";

test("two people create a room, invite, accept and chat both ways", async ({ browser }) => {
  const alice = await newUserPage(browser, "alice");
  const bob = await newUserPage(browser, "bob");

  // Empty states teach the next step.
  await expect(alice.page.getByTestId("room-list-empty")).toBeVisible();
  await expect(alice.page.getByRole("heading", { name: "No rooms yet" })).toBeVisible();

  const roomId = await createRoomViaUi(alice.page, { name: "Weekend plans", topic: "Hiking on Saturday" });
  await expect(alice.page.getByTestId("room-topic")).toHaveText("Hiking on Saturday");
  // Opening a room focuses the composer.
  await expect(alice.page.getByTestId("composer-input")).toBeFocused();
  // Room setup folds into one expandable line.
  const creation = alice.page.getByTestId("creation-summary");
  await expect(creation).toContainText("created and configured the room");
  await creation.locator("summary").click();
  await expect(creation.getByTestId("state-line").filter({ hasText: "changed the topic to “Hiking on Saturday”" })).toBeVisible();

  // Invite with validation first.
  await alice.page.getByTestId("open-invite").click();
  const invite = alice.page.getByTestId("invite-dialog");
  await invite.getByTestId("invite-user-id").fill("bob");
  await invite.getByTestId("invite-submit").click();
  await expect(invite.getByTestId("invite-user-id-error")).toContainText("full Matrix ID");
  await invite.getByTestId("invite-user-id").fill(bob.userId);
  await invite.getByTestId("invite-submit").click();
  await expect(invite).toBeHidden();
  await expect(alice.page.locator(`[data-testid="state-line"][data-event-type="m.room.member"]`).filter({ hasText: `invited ${bob.userId}` })).toBeVisible();

  await sendViaUi(alice.page, "Hello Bob");
  await expect(message(alice.page, "Hello Bob")).toBeVisible();

  // Bob sees the invite, named by the room name from stripped state.
  const inviteRow = bob.page.getByTestId("invite-row");
  await expect(inviteRow).toHaveAttribute("data-room-name", "Weekend plans");
  await expect(inviteRow).toContainText("Invited by");
  await inviteRow.getByTestId("accept-invite").click();
  await expect(bob.page.getByTestId("room-heading")).toHaveText("Weekend plans");
  await expect(message(bob.page, "Hello Bob")).toBeVisible();
  await expect(bob.page.getByTestId("invite-row")).toHaveCount(0);

  await sendViaUi(bob.page, "Hi Alice\nSee you there");
  await expect(message(alice.page, "Hi Alice\nSee you there")).toBeVisible();
  await expect(alice.page.getByTestId("state-line").filter({ hasText: "joined" }).last()).toBeVisible();

  // Unread: Bob looks elsewhere, Alice writes, Bob's board lights a lamp.
  await bob.page.getByTestId("open-settings").click();
  await expect(bob.page.getByRole("heading", { name: "Settings", level: 1 })).toBeFocused();
  await sendViaUi(alice.page, "Are you bringing snacks?");
  const bobRow = bob.page.locator(`[data-testid="room-row"][data-room-id="${roomId}"]`);
  await expect(bobRow.getByTestId("unread-badge")).toBeVisible();
  await expect(bobRow.getByTestId("room-preview")).toContainText("Are you bringing snacks?");
  await bobRow.click();
  await expect(message(bob.page, "Are you bringing snacks?")).toBeVisible();
  await expect(bobRow.getByTestId("unread-badge")).toHaveCount(0);

  // Member list.
  await openMembers(bob.page);
  const panel = bob.page.getByTestId("member-panel");
  await expect(panel.getByTestId("member-row")).toHaveCount(2);
  await expect(panel.locator(`[data-user-id="${alice.userId}"]`)).toContainText("Admin");

  // Sender grouping: Alice's two consecutive messages share one header.
  await sendViaUi(alice.page, "One more thing");
  await expect(message(alice.page, "One more thing")).toHaveClass(/msg-grouped/);

  // Day separator is shown.
  await expect(alice.page.getByTestId("day-separator").first()).toHaveText("Today");

  await alice.page.context().close();
  await bob.page.context().close();
});

test("a session survives reload and sign-out revokes it", async ({ browser }) => {
  const { page } = await newUserPage(browser, "carol");
  await createRoomViaUi(page, { name: "Notebook" });
  await sendViaUi(page, "remember me");
  await expect(message(page, "remember me")).toBeVisible();
  await awaitIdle(page);

  await page.reload();
  // Cached rooms render immediately; sync resumes from the stored token.
  await expect(page.getByTestId("room-heading")).toHaveText("Notebook");
  await expect(message(page, "remember me")).toBeVisible();
  await expectLive(page);

  const token = await page.evaluate(() => JSON.parse(localStorage.getItem("conduit:session") ?? "{}").accessToken as string);
  expect(token).toBeTruthy();
  expect((await apiWhoami(token)).user_id).toBeTruthy();

  await page.getByTestId("open-settings").click();
  await page.getByTestId("sign-out").click();
  await expect(page.getByTestId("login-form")).toBeVisible();
  await expect(page.getByTestId("signin-notice")).toHaveText("You have signed out.");
  expect(await page.evaluate(() => localStorage.getItem("conduit:session"))).toBeNull();
  const revoked = await apiWhoami(token, 401);
  expect(revoked.errcode).toBe("M_UNKNOWN_TOKEN");

  await page.reload();
  await expect(page.getByTestId("login-form")).toBeVisible();
  await page.context().close();
});

test("display name changes show on the board and in rooms", async ({ browser }) => {
  const { page } = await newUserPage(browser, "dana");
  await createRoomViaUi(page, { name: "Studio" });
  // React StrictMode starts two profile loads. Resolve the superseded load
  // only after the current load has made the form editable.
  let releaseStale!: () => void;
  const staleReady = new Promise<void>((resolve) => { releaseStale = resolve; });
  let profileLoads = 0;
  await page.route("**/_matrix/client/v3/profile/*", async (route) => {
    if (route.request().method() !== "GET" || ++profileLoads !== 1) {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    await staleReady;
    await route.fulfill({ response });
  });
  await page.getByTestId("open-settings").click();
  const input = page.getByTestId("displayname-input");
  await expect(input).toBeVisible();
  await input.fill("Dana Scully");
  const staleResponse = page.waitForResponse((r) => r.request().method() === "GET" && r.url().includes("/v3/profile/"));
  releaseStale();
  await (await staleResponse).finished();
  // Let React commit work caused by the completed response before saving.
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(input).toHaveValue("Dana Scully");
  await page.getByTestId("displayname-save").click();
  await expect(page.getByTestId("displayname-status")).toHaveText("Display name saved.");
  await expect(page.getByTestId("account-name")).toHaveText("Dana Scully");

  await page.getByTestId("room-row").first().click();
  await sendViaUi(page, "new name, who dis");
  await expect(message(page, "new name, who dis").getByTestId("message-sender")).toHaveText("Dana Scully");
  await expect(page.getByTestId("state-line").filter({ hasText: "set their display name to Dana Scully" })).toBeVisible();
  await page.context().close();
});

test("declining an invite removes it", async ({ browser }) => {
  const alice = await newUserPage(browser, "erin");
  const bob = await newUserPage(browser, "frank");
  await createRoomViaUi(alice.page, { name: "Not for Frank" });
  await alice.page.getByTestId("open-invite").click();
  await alice.page.getByTestId("invite-user-id").fill(bob.userId);
  await alice.page.getByTestId("invite-submit").click();
  const row = bob.page.getByTestId("invite-row");
  await expect(row).toBeVisible();
  await row.getByTestId("decline-invite").click();
  await expect(bob.page.getByTestId("invite-row")).toHaveCount(0);
  await expect(alice.page.getByTestId("state-line").filter({ hasText: "declined the invitation" })).toBeVisible();
  await alice.page.context().close();
  await bob.page.context().close();
});

test("join by room ID, validate addresses, and leave", async ({ browser }) => {
  const owner = await newUserPage(browser, "gail");
  const roomId = await createRoomViaUi(owner.page, { name: "Town square", visibility: "public" });
  const guest = await newUserPage(browser, "hank");

  await guest.page.getByTestId("open-join-room").click();
  const dialog = guest.page.getByTestId("join-room-dialog");
  await dialog.getByTestId("join-room-address").fill("town square");
  await dialog.getByTestId("join-room-submit").click();
  await expect(dialog.getByTestId("join-room-address-error")).toBeVisible();
  await dialog.getByTestId("join-room-address").fill(`#nowhere-${Date.now()}:${new URL(process.env.CONDUIT_E2E_HS!).hostname}`);
  await dialog.getByTestId("join-room-submit").click();
  await expect(dialog.getByTestId("join-room-error")).toBeVisible();
  await dialog.getByTestId("join-room-address").fill(roomId);
  await dialog.getByTestId("join-room-submit").click();
  await expect(dialog).toBeHidden();
  await expect(guest.page.getByTestId("room-heading")).toHaveText("Town square");
  await expect(owner.page.getByTestId("state-line").filter({ hasText: "joined" }).last()).toBeVisible();

  await guest.page.getByTestId("open-leave").click();
  const leave = guest.page.getByTestId("leave-dialog");
  await expect(leave).toContainText("rejoin later");
  await leave.getByTestId("leave-submit").click();
  await expect(guest.page.getByTestId("welcome")).toBeVisible();
  await expect(guest.page.getByTestId("room-row")).toHaveCount(0);
  await expect(owner.page.getByTestId("state-line").filter({ hasText: "left" }).last()).toBeVisible();
  await owner.page.context().close();
  await guest.page.context().close();
});
