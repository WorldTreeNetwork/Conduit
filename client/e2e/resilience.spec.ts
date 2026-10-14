// History, failure and recovery: back-pagination, failed sends with retry
// and delete, the reconnecting banner, and sign-in error states.
import { expect, test } from "@playwright/test";
import {
  PASSWORD,
  apiCreateRoom,
  apiRegister,
  apiSend,
  appUrl,
  awaitIdle,
  createRoomViaUi,
  expectLive,
  loginViaUi,
  message,
  newUserPage,
  sendViaUi,
  uniqueName,
} from "./support";

test("scrolling back pages history until the start of the room", async ({ page }) => {
  const seeder = await apiRegister("ivy");
  const roomId = await apiCreateRoom(seeder, { name: "Archive", preset: "private_chat" });
  for (let i = 1; i <= 75; i++) await apiSend(seeder, roomId, `history ${i}`, `seed-${i}`);

  await loginViaUi(page, seeder.localpart);
  await page.locator(`[data-testid="room-row"][data-room-id="${roomId}"]`).click();
  await expect(page.getByTestId("room-heading")).toHaveText("Archive");
  await expect(message(page, "history 75")).toBeVisible();

  // The initial sync window is 30 events; older ones arrive via /messages.
  const timeline = page.getByTestId("timeline");
  await expect(page.getByTestId("timeline-start")).toBeHidden();
  for (let guard = 0; guard < 10; guard++) {
    if (await page.getByTestId("timeline-start").isVisible()) break;
    await timeline.evaluate((el) => (el.scrollTop = 0));
    const older = page.getByTestId("load-older");
    if (await older.isVisible()) await older.click();
    await awaitIdle(page);
  }
  await expect(page.getByTestId("timeline-start")).toHaveText("This is the beginning of Archive.");
  await expect(message(page, "history 1")).toBeVisible();
  // (The room's create/join events are hidden by the server's history
  // visibility filter today: conduit-y99.26. Not asserted until fixed.)

  // Every message exactly once, in order.
  const bodies = await page.getByTestId("message-body").allTextContents();
  expect(bodies).toEqual(Array.from({ length: 75 }, (_, i) => `history ${i + 1}`));

  // Scrolled away from the bottom, a jump-to-latest control appears.
  await expect(page.getByTestId("jump-to-latest")).toBeVisible();
  await page.getByTestId("jump-to-latest").click();
  await expect(page.getByTestId("jump-to-latest")).toBeHidden();
  await expect(message(page, "history 75")).toBeFocused();
});

test("a failed send shows inline retry and delete, and retry delivers once", async ({ browser }) => {
  const { page } = await newUserPage(browser, "jane");
  const roomId = await createRoomViaUi(page, { name: "Flaky line" });

  await page.route("**/send/m.room.message/**", (route) => route.abort("connectionrefused"));
  await sendViaUi(page, "first try");
  const failed = page.locator('[data-testid="pending-item"][data-status="failed"]');
  await expect(failed).toHaveCount(1);
  await expect(failed.getByTestId("send-failure")).toContainText("Not sent");
  await expect(failed.getByTestId("carrier-mark")).toHaveAttribute("data-state", "failed");
  const pending = await page.evaluate(() => window.__conduitClient!.pendingSends());
  expect(pending).toHaveLength(1);
  expect(pending[0]).toMatchObject({ roomId, status: "failed" });

  // A second failure that we throw away.
  await sendViaUi(page, "never mind");
  await expect(failed).toHaveCount(2);
  await failed.filter({ hasText: "never mind" }).getByTestId("discard-send").click();
  await expect(failed).toHaveCount(1);

  await page.unroute("**/send/m.room.message/**");
  await failed.getByTestId("retry-send").click();
  await expect(message(page, "first try")).toBeVisible();
  await expect(page.getByTestId("pending-item")).toHaveCount(0);
  await awaitIdle(page);
  const timeline = await page.evaluate((id) => window.__conduitClient!.timeline(id), roomId);
  expect(timeline.filter((e) => e.body === "first try")).toHaveLength(1);
  expect(timeline.filter((e) => e.body === "never mind")).toHaveLength(0);
  await page.context().close();
});

test("failed sends survive a reload and can be retried afterwards", async ({ browser }) => {
  const { page } = await newUserPage(browser, "kim");
  await createRoomViaUi(page, { name: "Persistence" });
  await page.route("**/send/m.room.message/**", (route) => route.abort("connectionrefused"));
  await sendViaUi(page, "keep this");
  await expect(page.locator('[data-testid="pending-item"][data-status="failed"]')).toHaveCount(1);
  await page.reload();
  await expect(page.locator('[data-testid="pending-item"][data-status="failed"]')).toHaveCount(1);
  await page.unroute("**/send/m.room.message/**");
  await page.getByTestId("retry-send").click();
  await expect(message(page, "keep this")).toBeVisible();
  await expect(page.getByTestId("pending-item")).toHaveCount(0);
  await page.context().close();
});

test("losing the sync connection shows a reconnecting banner and recovers", async ({ browser }) => {
  const { page } = await newUserPage(browser, "lee");
  await createRoomViaUi(page, { name: "Signal" });
  await page.route("**/_matrix/client/v3/sync**", (route) => route.abort("connectionreset"));
  // Our own message completes the in-flight long-poll; the next poll fails.
  await sendViaUi(page, "wake the line");
  const banner = page.getByTestId("connection-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toContainText("Reconnecting");
  await expect(page.getByTestId("sync-status")).toHaveAttribute("data-state", "reconnecting");
  expect(await page.evaluate(() => window.__conduitClient!.syncState)).toBe("reconnecting");

  await page.unroute("**/_matrix/client/v3/sync**");
  await page.getByTestId("retry-sync").click();
  await expectLive(page);
  await expect(banner).toBeHidden();
  await expect(message(page, "wake the line")).toBeVisible();
  await page.context().close();
});

test("sign-in validates input and explains server errors", async ({ page }) => {
  await page.goto(appUrl());
  await expect(page.getByTestId("homeserver-pinned")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in", level: 1 })).toBeFocused();

  await page.getByTestId("signin-submit").click();
  await expect(page.getByTestId("username-input-error")).toHaveText("Enter your username.");
  await expect(page.getByTestId("username-input")).toBeFocused();
  await expect(page.getByTestId("username-input")).toHaveAttribute("aria-invalid", "true");

  await page.getByTestId("username-input").fill(uniqueName("nobody"));
  await page.getByTestId("password-input").fill("wrong password");
  await page.getByTestId("signin-submit").click();
  await expect(page.getByTestId("signin-error")).toBeVisible();

  const taken = await apiRegister("taken");
  await page.getByTestId("signin-switch-mode").click();
  await page.getByTestId("username-input").fill("Bad Name");
  await page.getByTestId("password-input").fill("short");
  await page.getByTestId("confirm-input").fill("different");
  await page.getByTestId("signin-submit").click();
  await expect(page.getByTestId("username-input-error")).toContainText("lowercase");
  await expect(page.getByTestId("password-input-error")).toContainText("8 characters");
  await expect(page.getByTestId("confirm-input-error")).toContainText("don't match");

  await page.getByTestId("username-input").fill(taken.localpart);
  await page.getByTestId("password-input").fill(PASSWORD);
  await page.getByTestId("confirm-input").fill(PASSWORD);
  await page.getByTestId("signin-submit").click();
  await expect(page.getByTestId("signin-error")).toContainText("taken");

  // The right password signs in.
  await page.getByTestId("signin-switch-mode").click();
  await page.getByTestId("username-input").fill(taken.localpart);
  await page.getByTestId("password-input").fill(PASSWORD);
  await page.getByTestId("signin-submit").click();
  await expectLive(page);
  expect(await page.evaluate(() => window.__conduitClient!.userId)).toBe(taken.userId);
});

test("an unreachable homeserver is reported on the homeserver field", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("homeserver-input").fill("http://127.0.0.1:9");
  await page.getByTestId("username-input").fill("someone");
  await page.getByTestId("password-input").fill("whatever1");
  await page.getByTestId("signin-submit").click();
  await expect(page.getByTestId("homeserver-input-error")).toContainText("Can't reach");
  await expect(page.getByTestId("homeserver-input")).toBeFocused();
});
