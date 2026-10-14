// Accessibility: axe on every main screen (zero serious/critical
// violations), keyboard navigation through the room list and timeline, and
// live announcements.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import {
  apiInvite,
  apiRegister,
  apiSend,
  appUrl,
  createRoomViaUi,
  message,
  newUserPage,
  openMembers,
  sendViaUi,
} from "./support";

async function expectNoSeriousViolations(page: Page, label: string) {
  // Let finite entrance transitions settle so contrast is measured at rest.
  await page.waitForFunction(() =>
    document
      .getAnimations()
      .every((a) => a.playState !== "running" || a.effect?.getComputedTiming().iterations === Infinity),
  );
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(
    serious.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(" ")).join(", ")})`),
    `${label}: serious axe violations`,
  ).toEqual([]);
}

for (const scheme of ["light", "dark"] as const) {
  test(`main screens have no serious axe violations (${scheme})`, async ({ browser }) => {
    const context = await browser.newContext({ colorScheme: scheme });
    const page = await context.newPage();
    await page.goto(appUrl());
    await expect(page.getByTestId("login-form")).toBeVisible();
    await expectNoSeriousViolations(page, "sign in");
    await page.getByTestId("signin-submit").click();
    await expect(page.getByTestId("username-input-error")).toBeVisible();
    await expectNoSeriousViolations(page, "sign in with errors");

    const other = await apiRegister("axe-friend");
    const { localpart } = await (async () => {
      const name = `axe-${scheme}-${Date.now().toString(36)}`;
      await page.getByTestId("signin-switch-mode").click();
      await page.getByTestId("username-input").fill(name);
      await page.getByTestId("password-input").fill("correct horse battery");
      await page.getByTestId("confirm-input").fill("correct horse battery");
      await page.getByTestId("signin-submit").click();
      await expect(page.getByTestId("sync-status")).toHaveAttribute("data-state", "live");
      return { localpart: name };
    })();
    await expectNoSeriousViolations(page, "empty home");

    const roomId = await createRoomViaUi(page, { name: "Accessible room", topic: "Checked by axe" });
    await sendViaUi(page, "A message for the checker");
    await sendViaUi(page, "/me waves politely");
    await expect(message(page, "A message for the checker")).toBeVisible();
    const userId = await page.evaluate(() => window.__conduitClient!.userId!);
    expect(userId).toContain(localpart);
    const invitingRoom = await (await import("./support")).apiCreateRoom(other, { name: "Invitation", preset: "private_chat" });
    await apiInvite(other, invitingRoom, userId);
    await expect(page.getByTestId("invite-row")).toBeVisible();
    await openMembers(page);
    await expectNoSeriousViolations(page, "room view with invite and members");

    await page.route("**/send/m.room.message/**", (route) => route.abort("connectionrefused"));
    await sendViaUi(page, "this one fails");
    await expect(page.getByTestId("send-failure")).toBeVisible();
    await expectNoSeriousViolations(page, "failed send");
    await page.unroute("**/send/m.room.message/**");

    await page.getByTestId("open-create-room").click();
    await expect(page.getByTestId("create-room-dialog")).toBeVisible();
    await expectNoSeriousViolations(page, "create room dialog");
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("create-room-dialog")).toBeHidden();
    await expect(page.getByTestId("open-create-room")).toBeFocused();

    await page.getByTestId("open-settings").click();
    await expect(page.getByTestId("displayname-input")).toBeVisible();
    await expectNoSeriousViolations(page, "settings");
    expect(roomId).toBeTruthy();
    await context.close();
  });
}

test("keyboard: arrows move through rooms and messages; new messages are announced", async ({ browser }) => {
  const { page, userId } = await newUserPage(browser, "kbd");
  await createRoomViaUi(page, { name: "Alpha" });
  await sendViaUi(page, "alpha one");
  await sendViaUi(page, "alpha two");
  await createRoomViaUi(page, { name: "Beta" });
  await createRoomViaUi(page, { name: "Gamma" });

  // Roving tabindex: one tab stop in the list, arrows move within it.
  const rows = page.getByTestId("room-row");
  await expect(rows).toHaveCount(3);
  await rows.first().focus();
  await page.keyboard.press("ArrowDown");
  await expect(rows.nth(1)).toBeFocused();
  await page.keyboard.press("End");
  await expect(rows.nth(2)).toBeFocused();
  await expect(rows.nth(2)).toHaveAttribute("data-room-name", "Alpha");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("room-heading")).toHaveText("Alpha");
  await expect(page.getByTestId("composer-input")).toBeFocused();

  // Shift+Enter inserts a newline; Enter sends.
  await page.keyboard.type("line one");
  await page.keyboard.press("Shift+Enter");
  await page.keyboard.type("line two");
  await expect(page.getByTestId("composer-input")).toHaveValue("line one\nline two");
  await page.keyboard.press("Enter");
  await expect(message(page, "line one\nline two")).toBeVisible();

  // Timeline items are reachable and arrow-navigable.
  const last = message(page, "line one\nline two");
  await last.focus();
  await page.keyboard.press("ArrowUp");
  await expect(message(page, "alpha two")).toBeFocused();
  await page.keyboard.press("ArrowUp");
  await expect(message(page, "alpha one")).toBeFocused();

  // Another person's message is announced through the live region.
  const friend = await apiRegister("announcer");
  const roomId = await page.getByTestId("room-view").getAttribute("data-room-id");
  await page.getByTestId("open-invite").click();
  await page.getByTestId("invite-user-id").fill(friend.userId);
  await page.getByTestId("invite-submit").click();
  await expect(page.getByTestId("invite-dialog")).toBeHidden();
  const join = await fetch(`${process.env.CONDUIT_E2E_HS}/_matrix/client/v3/join/${encodeURIComponent(roomId!)}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${friend.accessToken}`, "Content-Type": "application/json" },
    body: "{}",
  });
  expect(join.status).toBe(200);
  await apiSend(friend, roomId!, "can you hear me", "announce-1");
  await expect(page.getByTestId("message-announcer")).toHaveText(`${friend.userId}: can you hear me`);
  expect(userId).toBeTruthy();
  await page.context().close();
});

test("reduced motion stops the carrier animation", async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: "reduce" });
  const page = await context.newPage();
  const { registerViaUi, uniqueName } = await import("./support");
  await registerViaUi(page, uniqueName("calm"));
  await createRoomViaUi(page, { name: "Calm" });
  let release: () => void = () => {};
  const held = new Promise<void>((r) => (release = r));
  await page.route("**/send/m.room.message/**", async (route) => {
    await held;
    await route.continue();
  });
  await sendViaUi(page, "slow carrier");
  const mark = page.locator('[data-testid="pending-item"] [data-testid="carrier-mark"][data-state="sending"]');
  await expect(mark).toBeVisible();
  const animation = await mark.locator(".carrier-fill").evaluate((el) => getComputedStyle(el).animationName);
  expect(animation).toBe("none");
  release();
  await expect(message(page, "slow carrier")).toBeVisible();
  await context.close();
});
