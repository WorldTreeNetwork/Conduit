// Account and session management against the real server: devices,
// password change, deactivation, transparent token refresh and the
// soft-logout re-authentication flow.
import { expect, test } from "@playwright/test";
import { PASSWORD, apiWhoami, awaitIdle, createRoomViaUi, expectLive, loginViaUi, message, newUserPage, sendViaUi } from "./support";

const session = (page: import("@playwright/test").Page) =>
  page.evaluate(() => JSON.parse(localStorage.getItem("conduit:session") ?? "null") as { accessToken: string; refreshToken?: string; deviceId: string } | null);

test("devices: list, rename, and sign out another session", async ({ browser }) => {
  const first = await newUserPage(browser, "dev");
  const secondContext = await browser.newContext();
  const second = await secondContext.newPage();
  await loginViaUi(second, first.localpart);
  const secondDevice = (await session(second))!.deviceId;

  await first.page.getByTestId("open-settings").click();
  const devices = first.page.getByTestId("devices");
  await expect(devices.getByTestId("device-row")).toHaveCount(2);
  const current = devices.locator('[data-testid="device-row"][data-current="true"]');
  await expect(current).toContainText("This device");

  await current.getByTestId("device-rename").click();
  await first.page.getByTestId("device-rename-input").fill("Field laptop");
  await first.page.getByTestId("device-rename-save").click();
  await expect(current).toContainText("Field laptop");

  const other = devices.locator(`[data-testid="device-row"][data-device-id="${secondDevice}"]`);
  await other.getByTestId("device-sign-out").click();
  await first.page.getByTestId("confirm-device-signout-password").fill("wrong password");
  await first.page.getByTestId("confirm-device-signout-submit").click();
  await expect(first.page.getByTestId("confirm-device-signout-password-error")).toHaveText("That password is not right.");
  await first.page.getByTestId("confirm-device-signout-password").fill(PASSWORD);
  await first.page.getByTestId("confirm-device-signout-submit").click();
  await expect(devices.getByTestId("device-row")).toHaveCount(1);

  // The signed-out session lands on sign-in with its local state wiped
  // (hard logout: the device is gone). Reload in case its long-poll has
  // not yet returned.
  await second.reload();
  await expect(second.getByTestId("login-form")).toBeVisible();
  expect(await session(second)).toBeNull();
  expect(await second.evaluate(() => localStorage.getItem("conduit:sync"))).toBeNull();
  await secondContext.close();
  await first.page.context().close();
});

test("change password, then sign in with the new one", async ({ browser }) => {
  const { page, localpart } = await newUserPage(browser, "pwd");
  await page.getByTestId("open-settings").click();
  const form = page.getByTestId("password-form");
  await form.getByTestId("password-current").fill("not my password");
  await form.getByTestId("password-new").fill("brand new secret");
  await form.getByTestId("password-confirm").fill("brand new secret");
  await form.getByTestId("password-save").click();
  await expect(form.getByTestId("password-current-error")).toHaveText("That password is not right.");
  await form.getByTestId("password-current").fill(PASSWORD);
  await form.getByTestId("password-logout-others").uncheck();
  await form.getByTestId("password-save").click();
  await expect(form.getByTestId("password-status")).toHaveText("Password changed.");
  // This session survives its own password change.
  await expectLive(page);

  const other = await (await browser.newContext()).newPage();
  await other.goto(`/?hs=${encodeURIComponent(process.env.CONDUIT_E2E_HS!)}`);
  await other.getByTestId("username-input").fill(localpart);
  await other.getByTestId("password-input").fill(PASSWORD);
  await other.getByTestId("signin-submit").click();
  await expect(other.getByTestId("signin-error")).toHaveText("That username and password don't match.");
  await other.getByTestId("password-input").fill("brand new secret");
  await other.getByTestId("signin-submit").click();
  await expectLive(other);
  await other.context().close();
  await page.context().close();
});

test("deactivating an account signs out and blocks sign-in", async ({ browser }) => {
  const { page, localpart } = await newUserPage(browser, "bye");
  const token = (await session(page))!.accessToken;
  await page.getByTestId("open-settings").click();
  await page.getByTestId("deactivate-open").click();
  await page.getByTestId("confirm-deactivate-password").fill(PASSWORD);
  await page.getByTestId("confirm-deactivate-submit").click();
  await expect(page.getByTestId("signin-notice")).toHaveText("Your account has been deactivated.");
  expect((await apiWhoami(token, 401)).errcode).toBe("M_UNKNOWN_TOKEN");
  await page.getByTestId("username-input").fill(localpart);
  await page.getByTestId("password-input").fill(PASSWORD);
  await page.getByTestId("signin-submit").click();
  await expect(page.getByTestId("signin-error")).toBeVisible();
  await page.context().close();
});

test("an expired access token is refreshed transparently", async ({ browser }) => {
  const { page } = await newUserPage(browser, "fresh");
  await createRoomViaUi(page, { name: "Refreshing" });
  const before = (await session(page))!;
  expect(before.refreshToken).toBeTruthy();
  // The server reports expiry once (soft logout); the client refreshes and retries.
  let expired = false;
  await page.route("**/_matrix/client/v3/rooms/*/send/**", async (route) => {
    if (!expired) {
      expired = true;
      await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ errcode: "M_UNKNOWN_TOKEN", error: "expired", soft_logout: true }) });
    } else {
      await route.continue();
    }
  });
  await sendViaUi(page, "still here");
  await expect(message(page, "still here")).toBeVisible();
  const after = (await session(page))!;
  expect(after.accessToken).not.toBe(before.accessToken);
  expect(after.deviceId).toBe(before.deviceId);
  expect((await apiWhoami(after.accessToken)).device_id).toBe(before.deviceId);
  await page.context().close();
});

test("soft logout keeps the device and its data and re-authenticates in place", async ({ browser }) => {
  const { page, userId } = await newUserPage(browser, "soft");
  await createRoomViaUi(page, { name: "Kept rooms" });
  await sendViaUi(page, "before expiry");
  await expect(message(page, "before expiry")).toBeVisible();
  await awaitIdle(page);
  const before = (await session(page))!;

  const soft = JSON.stringify({ errcode: "M_UNKNOWN_TOKEN", error: "expired", soft_logout: true });
  await page.route("**/_matrix/client/v3/refresh", (route) => route.fulfill({ status: 401, contentType: "application/json", body: soft }));
  await page.route("**/_matrix/client/v3/rooms/*/send/**", (route) => route.fulfill({ status: 401, contentType: "application/json", body: soft }));
  await sendViaUi(page, "during expiry");

  await expect(page.getByTestId("reauth")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Your session expired" })).toBeFocused();
  await page.unroute("**/_matrix/client/v3/refresh");
  await page.unroute("**/_matrix/client/v3/rooms/*/send/**");
  await page.getByTestId("reauth-password").fill("wrong");
  await page.getByTestId("reauth-submit").click();
  await expect(page.getByTestId("reauth-password-error")).toHaveText("That password is not right.");
  await page.getByTestId("reauth-password").fill(PASSWORD);
  await page.getByTestId("reauth-submit").click();

  await expect(page.getByTestId("room-heading")).toHaveText("Kept rooms");
  await expect(message(page, "before expiry")).toBeVisible();
  await expectLive(page);
  const after = (await session(page))!;
  expect(after.deviceId).toBe(before.deviceId);
  expect(after.accessToken).not.toBe(before.accessToken);
  expect((await apiWhoami(after.accessToken)).user_id).toBe(userId);
  // The message that failed during expiry can be retried now.
  await page.locator('[data-testid="pending-item"][data-status="failed"]').getByTestId("retry-send").click();
  await expect(message(page, "during expiry")).toBeVisible();
  await page.context().close();
});
