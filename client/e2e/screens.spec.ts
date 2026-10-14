// Visual review captures (not assertions). Run with CONDUIT_CAPTURE=1 to
// write desktop/mobile, light/dark screenshots into .impeccable/review/.
import { expect, test } from "@playwright/test";
import { apiCreateRoom, apiInvite, apiRegister, apiSend, appUrl, loginViaUi, message } from "./support";

test.skip(!process.env.CONDUIT_CAPTURE, "set CONDUIT_CAPTURE=1 to capture review screenshots");

test("capture review screens", async ({ browser }) => {
  const me = await apiRegister("rowan");
  const friend = await apiRegister("sasha");
  const setName = (user: typeof me, name: string) =>
    fetch(`${process.env.CONDUIT_E2E_HS}/_matrix/client/v3/profile/${encodeURIComponent(user.userId)}/displayname`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${user.accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ displayname: name }),
    });
  await setName(me, "Rowan Pike");
  await setName(friend, "Sasha Okafor");
  const room = await apiCreateRoom(me, { name: "Field crew", topic: "Saturday survey of the east ridge", preset: "public_chat" });
  const equipment = await apiCreateRoom(me, { name: "Equipment", preset: "public_chat" });
  const join = await fetch(`${process.env.CONDUIT_E2E_HS}/_matrix/client/v3/join/${encodeURIComponent(room)}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${friend.accessToken}`, "Content-Type": "application/json" },
    body: "{}",
  });
  expect(join.status).toBe(200);
  const join2 = await fetch(`${process.env.CONDUIT_E2E_HS}/_matrix/client/v3/join/${encodeURIComponent(equipment)}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${friend.accessToken}`, "Content-Type": "application/json" },
    body: "{}",
  });
  expect(join2.status).toBe(200);
  const lines: [typeof me, string][] = [
    [friend, "Morning! Are we still on for the ridge survey?"],
    [me, "Yes. Meet at the trailhead at 7:30."],
    [me, "I'll bring the level and two tripods."],
    [friend, "Great. Forecast says clear until noon, wind picking up after."],
    [friend, "Map of the route: https://example.org/maps/east-ridge"],
    [me, "Perfect. We should be off the exposed section by 11."],
  ];
  let n = 0;
  for (const [who, body] of lines) await apiSend(who, room, body, `cap-${n++}`);
  const other = await apiCreateRoom(friend, { name: "Weekend kitchen", preset: "private_chat" });
  await apiInvite(friend, other, me.userId);

  for (const scheme of ["light", "dark"] as const) {
    for (const [label, viewport] of [
      ["desktop", { width: 1440, height: 900 }],
      ["mobile", { width: 390, height: 844 }],
    ] as const) {
      const context = await browser.newContext({ colorScheme: scheme, viewport });
      const page = await context.newPage();
      if (label === "desktop" && scheme === "light") {
        await page.goto(appUrl());
        await expect(page.getByTestId("login-form")).toBeVisible();
        await page.screenshot({ path: `.impeccable/review/signin-${scheme}.png` });
      }
      await loginViaUi(page, me.localpart);
      if (label === "mobile") await page.screenshot({ path: `.impeccable/review/${label}-board-${scheme}.png` });
      await page.locator(`[data-testid="room-row"][data-room-id="${room}"]`).click();
      await expect(message(page, "Perfect. We should be off the exposed section by 11.")).toBeVisible();
      await apiSend(friend, equipment, `Tripod legs are in the van (${scheme} ${label})`, `eq-${scheme}-${label}`);
      await expect(page.locator(`[data-testid="room-row"][data-room-id="${equipment}"]`).getByTestId("unread-badge")).toHaveCount(1);
      await page.route("**/send/m.room.message/**", (route) => route.abort("connectionrefused"));
      await page.getByTestId("composer-input").fill("Running five minutes late");
      await page.getByTestId("composer-input").press("Enter");
      await expect(page.getByTestId("send-failure")).toBeVisible();
      await page.unroute("**/send/m.room.message/**");
      await page.route("**/send/m.room.message/**", () => undefined);
      await page.getByTestId("composer-input").fill("On my way");
      await page.getByTestId("composer-input").press("Enter");
      await expect(page.locator('[data-testid="pending-item"][data-status="sending"]')).toBeVisible();
      await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getComputedTiming().iterations === Infinity));
      await page.screenshot({ path: `.impeccable/review/${label === "desktop" ? "desktop" : "mobile"}-${scheme}.png` });
      await context.close();
    }
  }
});
