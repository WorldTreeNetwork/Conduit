// Shared e2e helpers. Every wait is on observable state (DOM, the
// window.__conduitClient hook, or a server response); there are no sleeps.
import { expect, type Browser, type Page } from "@playwright/test";

export const PASSWORD = "correct horse battery";

export function hs(): string {
  const url = process.env.CONDUIT_E2E_HS;
  if (!url) throw new Error("CONDUIT_E2E_HS is not set; global setup did not run");
  return url;
}

export function serverName(): string {
  return process.env.CONDUIT_E2E_SERVER_NAME ?? new URL(hs()).hostname;
}

let seq = 0;
/** A fresh, valid localpart per call (tests share one server). */
export function uniqueName(prefix: string): string {
  seq += 1;
  return `${prefix}-${Date.now().toString(36)}${seq}${Math.random().toString(36).slice(2, 6)}`;
}

export function mxid(localpart: string): string {
  return `@${localpart}:${serverName()}`;
}

export function appUrl(path = "/"): string {
  return `${path}?hs=${encodeURIComponent(hs())}`;
}

export async function awaitIdle(page: Page): Promise<void> {
  await page.waitForFunction(() => !!window.__conduitClient?.signedIn);
  await page.evaluate(() => window.__conduitClient!.awaitIdle(20_000));
}

export async function expectLive(page: Page): Promise<void> {
  await expect(page.getByTestId("sync-status")).toHaveAttribute("data-state", "live");
}

/** Register through the UI and wait for the first sync. */
export async function registerViaUi(page: Page, localpart: string): Promise<void> {
  await page.goto(appUrl());
  await page.getByTestId("signin-switch-mode").click();
  await expect(page.getByRole("heading", { name: "Create an account" })).toBeVisible();
  await page.getByTestId("username-input").fill(localpart);
  await page.getByTestId("password-input").fill(PASSWORD);
  await page.getByTestId("confirm-input").fill(PASSWORD);
  await page.getByTestId("signin-submit").click();
  await expectLive(page);
  await awaitIdle(page);
}

export async function loginViaUi(page: Page, localpart: string): Promise<void> {
  await page.goto(appUrl());
  await page.getByTestId("username-input").fill(localpart);
  await page.getByTestId("password-input").fill(PASSWORD);
  await page.getByTestId("signin-submit").click();
  await expectLive(page);
  await awaitIdle(page);
}

export async function newUserPage(browser: Browser, prefix: string): Promise<{ page: Page; localpart: string; userId: string }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const localpart = uniqueName(prefix);
  await registerViaUi(page, localpart);
  return { page, localpart, userId: mxid(localpart) };
}

export async function createRoomViaUi(
  page: Page,
  options: { name: string; topic?: string; visibility?: "private" | "public" },
): Promise<string> {
  await page.getByTestId("open-create-room").click();
  const dialog = page.getByTestId("create-room-dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByTestId("create-room-name").fill(options.name);
  if (options.topic) await dialog.getByTestId("create-room-topic").fill(options.topic);
  await dialog.getByTestId(options.visibility === "public" ? "create-room-public" : "create-room-private").check();
  await dialog.getByTestId("create-room-submit").click();
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("room-heading")).toHaveText(options.name);
  const roomId = await page.getByTestId("room-view").getAttribute("data-room-id");
  expect(roomId).toBeTruthy();
  return roomId!;
}

export async function sendViaUi(page: Page, text: string): Promise<void> {
  const input = page.getByTestId("composer-input");
  await input.fill(text);
  await input.press("Enter");
  await expect(input).toHaveValue("");
}

/** Open the people panel (it starts open on wide screens). */
export async function openMembers(page: Page): Promise<void> {
  const toggle = page.getByTestId("toggle-members");
  if ((await toggle.getAttribute("aria-pressed")) !== "true") await toggle.click();
  await expect(page.getByTestId("member-panel")).toBeVisible();
}

/** The settled (server-confirmed) message with this body in the open room. */
export function message(page: Page, body: string) {
  return page.locator('[data-testid="timeline-item"]', { has: page.getByTestId("message-body").getByText(body, { exact: true }) });
}

// ---- Direct API access for seeding (never used to assert UI behaviour) ----

export interface ApiUser {
  userId: string;
  accessToken: string;
  localpart: string;
}

async function api<T>(method: string, path: string, token?: string, body?: unknown, expected = 200): Promise<T> {
  const response = await fetch(`${hs()}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  if (response.status !== expected) throw new Error(`${method} ${path}: ${response.status} ${text}`);
  return (text ? JSON.parse(text) : {}) as T;
}

export async function apiRegister(prefix: string): Promise<ApiUser> {
  const localpart = uniqueName(prefix);
  const challenge = await api<{ session: string }>(
    "POST",
    "/_matrix/client/v3/register",
    undefined,
    { username: localpart, password: PASSWORD },
    401,
  );
  const done = await api<{ user_id: string; access_token: string }>("POST", "/_matrix/client/v3/register", undefined, {
    username: localpart,
    password: PASSWORD,
    auth: { type: "m.login.dummy", session: challenge.session },
  });
  return { userId: done.user_id, accessToken: done.access_token, localpart };
}

export async function apiCreateRoom(user: ApiUser, body: Record<string, unknown>): Promise<string> {
  const { room_id } = await api<{ room_id: string }>("POST", "/_matrix/client/v3/createRoom", user.accessToken, body);
  return room_id;
}

export async function apiSend(user: ApiUser, roomId: string, body: string, txnId: string): Promise<string> {
  const { event_id } = await api<{ event_id: string }>(
    "PUT",
    `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/${encodeURIComponent(txnId)}`,
    user.accessToken,
    { msgtype: "m.text", body },
  );
  return event_id;
}

export async function apiInvite(user: ApiUser, roomId: string, userId: string): Promise<void> {
  await api("POST", `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/invite`, user.accessToken, { user_id: userId });
}

export async function apiWhoami(token: string, expected = 200): Promise<Record<string, unknown>> {
  return api("GET", "/_matrix/client/v3/account/whoami", token, undefined, expected);
}
