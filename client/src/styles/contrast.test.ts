// WCAG AA guard for the design tokens: every text/background pair the UI uses
// must stay >= 4.5:1 (3:1 for large text and non-text indicators), in both
// the light and the dark theme.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const css = readFileSync(fileURLToPath(new URL("./tokens.css", import.meta.url)), "utf8");

function block(selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  const open = css.indexOf("{", start);
  const close = css.indexOf("}", open);
  const vars: Record<string, string> = {};
  for (const match of css.slice(open, close).matchAll(/--(color-[\w-]+):\s*(#[0-9a-f]{6})/gi)) {
    vars[match[1]!] = match[2]!;
  }
  return vars;
}

const light = block(":root {");
const dark = { ...light, ...block(':root[data-theme="dark"]') };

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const TEXT: [string, string][] = [
  ["ink", "ground"],
  ["ink", "surface"],
  ["ink", "surface-sunk"],
  ["ink-muted", "ground"],
  ["ink-muted", "surface"],
  ["ink-faint", "surface"],
  ["ink-faint", "ground"],
  ["ink-faint", "surface-hover"],
  ["ink-muted", "surface-hover"],
  ["ink-muted", "surface-sunk"],
  ["ink-faint", "surface-sunk"],
  ["signal-ink", "signal-surface"],
  ["brass-text", "caution-surface"],
  ["board-ink", "board"],
  ["board-ink", "board-raised"],
  ["board-ink", "board-selected"],
  ["board-ink-muted", "board"],
  ["board-ink-muted", "board-selected"],
  ["board-ink-muted", "board-raised"],
  ["brass-ink", "brass"],
  ["brass-ink", "brass-strong"],
  ["brass-text", "surface"],
  ["brass-text", "ground"],
  ["lamp-ink", "lamp"],
  ["signal-ink", "signal-surface"],
  ["signal", "surface"],
  ["signal-on", "signal"],
  ["clear", "surface"],
  ["caution-ink", "caution-surface"],
  ["tint-0-ink", "tint-0"],
  ["tint-1-ink", "tint-1"],
  ["tint-2-ink", "tint-2"],
  ["tint-3-ink", "tint-3"],
  ["tint-4-ink", "tint-4"],
  ["tint-5-ink", "tint-5"],
  ["board-signal", "board"],
  ["board-signal", "board-selected"],
];

const NON_TEXT: [string, string][] = [
  ["focus", "ground"],
  ["focus", "surface"],
  ["lamp", "board"],
  ["board-clear", "board"],
  ["board-signal", "board"],
  ["rule-strong", "surface"],
];

it("keeps the media-query dark theme identical to the forced dark theme", () => {
  const media = block(':root:not([data-theme="light"])');
  expect(media).toEqual(block(':root[data-theme="dark"]'));
});

describe.each([
  ["light", light],
  ["dark", dark],
])("%s theme contrast", (_name, theme) => {
  it.each(TEXT)("%s on %s >= 4.5", (fg, bg) => {
    expect(theme[`color-${fg}`], fg).toBeDefined();
    expect(theme[`color-${bg}`], bg).toBeDefined();
    expect(contrast(theme[`color-${fg}`]!, theme[`color-${bg}`]!)).toBeGreaterThanOrEqual(4.5);
  });
  it.each(NON_TEXT)("%s on %s >= 3", (fg, bg) => {
    expect(contrast(theme[`color-${fg}`]!, theme[`color-${bg}`]!)).toBeGreaterThanOrEqual(3);
  });
});
