// Phase 2 journeys against the real server: reactions, replies, edits,
// deletions, threads, typing, read receipts, media, room settings, the
// public directory and user search.
import { expect, test, type Page } from "@playwright/test";
import { awaitIdle, createRoomViaUi, message, newUserPage, openMembers, sendViaUi } from "./support";

/** Two people in one room, both looking at it. */
async function pairInRoom(browser: import("@playwright/test").Browser, name: string) {
  const alice = await newUserPage(browser, "ann");
  const bob = await newUserPage(browser, "ben");
  const roomId = await createRoomViaUi(alice.page, { name });
  await alice.page.getByTestId("open-invite").click();
  await alice.page.getByTestId("invite-user-id").fill(bob.userId);
  await alice.page.getByTestId("invite-submit").click();
  await expect(alice.page.getByTestId("invite-dialog")).toBeHidden();
  await bob.page.getByTestId("invite-row").getByTestId("accept-invite").click();
  await expect(bob.page.getByTestId("room-heading")).toHaveText(name);
  return { alice, bob, roomId };
}

function actions(page: Page, body: string) {
  const row = message(page, body);
  return {
    row,
    async open() {
      await row.hover();
      await expect(row.getByTestId("message-actions")).toBeVisible();
    },
  };
}

test("reactions, replies, edits, deletions and threads between two people", async ({ browser }) => {
  const { alice, bob } = await pairInRoom(browser, "Relations");
  await sendViaUi(bob.page, "first message");
  await expect(message(alice.page, "first message")).toBeVisible();

  // React from the action toolbar; both sides see the count.
  const a = actions(alice.page, "first message");
  await a.open();
  await a.row.getByTestId("action-react").click();
  await a.row.getByRole("button", { name: "React with 👍" }).click();
  await expect(message(bob.page, "first message").locator('[data-testid="reaction"][data-key="👍"]')).toHaveAttribute("data-count", "1");
  // Bob joins in by clicking the existing reaction.
  await message(bob.page, "first message").locator('[data-testid="reaction"][data-key="👍"]').click();
  const aliceThumbs = message(alice.page, "first message").locator('[data-testid="reaction"][data-key="👍"]');
  await expect(aliceThumbs).toHaveAttribute("data-count", "2");
  await expect(aliceThumbs).toHaveAttribute("aria-pressed", "true");
  // Clicking your own reaction removes it (redaction).
  await aliceThumbs.click();
  await expect(aliceThumbs).toHaveAttribute("data-count", "1");
  await expect(message(bob.page, "first message").locator('[data-testid="reaction"][data-key="👍"]')).toHaveAttribute("data-count", "1");

  // Reply: the quote names the original.
  await a.open();
  await a.row.getByTestId("action-reply").click();
  await expect(alice.page.getByTestId("composer-context")).toHaveAttribute("data-kind", "reply");
  await sendViaUi(alice.page, "a reply");
  await expect(alice.page.getByTestId("composer-context")).toHaveCount(0);
  const replyOnBob = message(bob.page, "a reply");
  await expect(replyOnBob.getByTestId("reply-quote")).toContainText("first message");

  // Edit the last own message with ArrowUp; Bob sees the new text, marked edited.
  await alice.page.getByTestId("composer-input").focus();
  await alice.page.keyboard.press("ArrowUp");
  await expect(alice.page.getByTestId("composer-context")).toHaveAttribute("data-kind", "edit");
  await expect(alice.page.getByTestId("composer-input")).toHaveValue("a reply");
  await alice.page.getByTestId("composer-input").fill("a better reply");
  await alice.page.keyboard.press("Enter");
  const edited = bob.page.locator('[data-testid="timeline-item"]', { hasText: "a better reply" });
  await expect(edited.getByTestId("edited-marker")).toBeVisible();
  await expect(edited.getByTestId("reply-quote")).toContainText("first message");
  // The edit is not a separate message.
  await expect(bob.page.locator('[data-testid="timeline-item"]', { hasText: "* a better reply" })).toHaveCount(0);

  // Delete with a reason.
  await sendViaUi(alice.page, "regrettable");
  const r = actions(alice.page, "regrettable");
  await r.open();
  await r.row.getByTestId("action-delete").click();
  await alice.page.getByTestId("delete-reason").fill("typo");
  await alice.page.getByTestId("delete-submit").click();
  await expect(alice.page.getByTestId("delete-dialog")).toBeHidden();
  await expect(message(bob.page, "regrettable")).toHaveCount(0);
  await expect(bob.page.getByTestId("message-body").filter({ hasText: "Message deleted" })).toHaveCount(1);

  // Thread: Bob starts one; Alice sees the summary, opens it and answers.
  const b = actions(bob.page, "first message");
  await b.open();
  await b.row.getByTestId("action-thread").click();
  const bobThread = bob.page.getByTestId("thread-panel");
  await expect(bobThread).toBeVisible();
  await expect(bob.page.getByTestId("thread-composer-input")).toBeFocused();
  await bob.page.getByTestId("thread-composer-input").fill("side discussion");
  await bob.page.keyboard.press("Enter");
  await expect(message(bob.page, "side discussion")).toBeVisible();
  const summary = message(alice.page, "first message").getByTestId("thread-summary");
  await expect(summary).toHaveAttribute("data-count", "1");
  // Thread replies stay out of the main timeline.
  await expect(alice.page.getByTestId("timeline").locator('[data-testid="message-body"]', { hasText: "side discussion" })).toHaveCount(0);
  await summary.click();
  const aliceThread = alice.page.getByTestId("thread-panel");
  await expect(aliceThread.getByTestId("message-body").filter({ hasText: "side discussion" })).toBeVisible();
  await alice.page.getByTestId("thread-composer-input").fill("agreed, in thread");
  await alice.page.keyboard.press("Enter");
  await expect(bobThread.getByTestId("message-body").filter({ hasText: "agreed, in thread" })).toBeVisible();
  await expect(message(bob.page, "first message").getByTestId("thread-summary")).toHaveAttribute("data-count", "2");

  await alice.page.context().close();
  await bob.page.context().close();
});

test("typing indicators and read receipts", async ({ browser }) => {
  const { alice, bob } = await pairInRoom(browser, "Signals");
  await alice.page.getByTestId("composer-input").pressSequentially("hello th");
  const typing = bob.page.getByTestId("typing-indicator");
  await expect(typing).toHaveAttribute("data-count", "1");
  await expect(typing).toContainText("is typing");
  await alice.page.keyboard.press("Enter");
  await expect(typing).toHaveAttribute("data-count", "0");
  await expect(message(bob.page, "hello th")).toBeVisible();
  // Bob is looking at the latest message, so his receipt reaches Alice.
  await expect(message(alice.page, "hello th").getByTestId("read-receipts")).toHaveAttribute("data-readers", bob.userId);
  await alice.page.context().close();
  await bob.page.context().close();
});

const PNG_2x2 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAEUlEQVR4nGPQKfT4D8IMMAYAP4IHkZWsd2kAAAAASUVORK5CYII=",
  "base64",
);

test("images and files upload, preview and download through authenticated media", async ({ browser }) => {
  const { alice, bob } = await pairInRoom(browser, "Media");
  await alice.page.getByTestId("attach-input").setInputFiles({ name: "dot.png", mimeType: "image/png", buffer: PNG_2x2 });
  const bobImage = bob.page.getByTestId("media-image-img");
  await expect(bobImage).toBeVisible();
  await expect(bobImage).toHaveAttribute("alt", "dot.png");
  await expect.poll(() => bobImage.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
  // The preview comes from the authenticated v1 endpoint as a blob URL.
  expect(await bobImage.getAttribute("src")).toMatch(/^blob:/);

  await alice.page.getByTestId("attach-input").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("field notes") });
  const card = bob.page.getByTestId("file-card").filter({ hasText: "notes.txt" });
  await expect(card).toContainText("11 B");
  const [download] = await Promise.all([bob.page.waitForEvent("download"), card.getByTestId("file-download").click()]);
  expect(download.suggestedFilename()).toBe("notes.txt");
  const path = await download.path();
  expect((await import("node:fs")).readFileSync(path!, "utf8")).toBe("field notes");
  await alice.page.context().close();
  await bob.page.context().close();
});

test("room settings: rename, topic, history and roles", async ({ browser }) => {
  const { alice, bob } = await pairInRoom(browser, "Before");
  await alice.page.getByTestId("open-room-settings").click();
  const dialog = alice.page.getByTestId("room-settings-dialog");
  await dialog.getByTestId("room-settings-name").fill("After");
  await dialog.getByTestId("room-settings-topic").fill("Renamed by the admin");
  await dialog.getByTestId("room-settings-history").selectOption("joined");
  await dialog.getByTestId("room-settings-save").click();
  await expect(dialog.getByTestId("room-settings-status")).toHaveText("Saved.");
  await expect(bob.page.getByTestId("room-heading")).toHaveText("After");
  await expect(bob.page.getByTestId("room-topic")).toHaveText("Renamed by the admin");
  await expect(bob.page.getByTestId("state-line").filter({ hasText: "members since they joined" })).toBeVisible();

  const bobRole = dialog.locator(`[data-testid="role-row"][data-user-id="${bob.userId}"]`).getByTestId("role-select");
  await bobRole.selectOption("50");
  await expect(dialog.getByTestId("room-settings-status")).toContainText("Moderator");
  await alice.page.keyboard.press("Escape");
  await openMembers(bob.page);
  await expect(bob.page.getByTestId("member-panel").locator(`[data-user-id="${bob.userId}"]`)).toContainText("Moderator");
  // As a moderator Bob can now open the editable settings.
  await bob.page.getByTestId("open-room-settings").click();
  await expect(bob.page.getByTestId("room-settings-dialog").getByTestId("room-settings-name")).toBeVisible();
  await alice.page.context().close();
  await bob.page.context().close();
});

test("public room directory and user search", async ({ browser }) => {
  const owner = await newUserPage(browser, "dir");
  const plaza = `Plaza ${Date.now().toString(36)}`;
  const roomId = await createRoomViaUi(owner.page, { name: plaza, visibility: "public", topic: "Open to all" });
  const visitor = await newUserPage(browser, "vis");
  await visitor.page.getByTestId("open-join-room").click();
  const dialog = visitor.page.getByTestId("join-room-dialog");
  await dialog.getByTestId("directory-search").fill(plaza);
  const row = dialog.locator(`[data-testid="directory-room"][data-room-id="${roomId}"]`);
  await expect(row).toContainText("Open to all");
  await row.getByTestId("directory-join").click();
  await expect(visitor.page.getByTestId("room-heading")).toHaveText(plaza);

  // Invite by searching the user directory (they share a room now).
  const third = await newUserPage(browser, "srch");
  // Sharing a public room makes the third user discoverable.
  await third.page.getByTestId("open-join-room").click();
  await third.page.getByTestId("join-room-address").fill(roomId);
  await third.page.getByTestId("join-room-submit").click();
  await expect(third.page.getByTestId("room-heading")).toHaveText(plaza);
  const privateRoom = await createRoomViaUi(owner.page, { name: "Back office" });
  expect(privateRoom).toBeTruthy();
  await owner.page.getByTestId("open-invite").click();
  await owner.page.getByTestId("invite-user-id").fill(third.localpart.slice(0, 8));
  const suggestion = owner.page.locator(`[data-testid="user-suggestion"][data-user-id="${third.userId}"]`);
  await expect(suggestion).toBeVisible();
  await suggestion.click();
  await expect(owner.page.getByTestId("invite-user-id")).toHaveValue(third.userId);
  await owner.page.getByTestId("invite-submit").click();
  await expect(third.page.getByTestId("invite-row")).toHaveAttribute("data-room-name", "Back office");
  await awaitIdle(owner.page);
  for (const p of [owner, visitor, third]) await p.page.context().close();
});
