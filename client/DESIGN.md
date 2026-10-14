---
name: Conduit
description: The first-party Matrix client for Conduit, built as a pneumatic-tube dispatch hall in station enamel.
colors:
  ground: "#e9eeea"
  surface: "#fbfcfa"
  surface-sunk: "#dfe6e1"
  surface-hover: "#e2e9e4"
  rule: "#c3cfc8"
  rule-strong: "#6c7f76"
  ink: "#13201c"
  ink-muted: "#48594f"
  ink-faint: "#53635b"
  board: "#163a33"
  board-raised: "#1e4a42"
  board-selected: "#24524a"
  board-ink: "#edf3ef"
  board-ink-muted: "#bfd2ca"
  board-rule: "#2d544b"
  board-clear: "#7fd3a0"
  board-signal: "#ffb4ab"
  brass: "#c48f2c"
  brass-strong: "#a8761a"
  brass-ink: "#1b1305"
  brass-text: "#835a0c"
  lamp: "#e2ad45"
  lamp-ink: "#1b1305"
  signal: "#b02a20"
  signal-surface: "#f8e4e1"
  signal-ink: "#7d1a12"
  clear: "#2c7148"
  caution-surface: "#f6ebcf"
  caution-ink: "#5c4108"
  focus: "#163a33"
  selection: "#f3d891"
  scrim: "rgb(10 22 19 / 0.45)"
  lamp-halo: "rgb(226 173 69 / 0.28)"
  signal-halo: "rgb(255 157 146 / 0.3)"
  clear-halo: "rgb(127 211 160 / 0.24)"
  tint-0: "#f0d9a0"
  tint-0-ink: "#2b1d02"
  tint-1: "#b9dccb"
  tint-1-ink: "#0d2a23"
  tint-2: "#f2c0b6"
  tint-2-ink: "#3a120b"
  tint-3: "#c3cdd8"
  tint-3-ink: "#18232e"
  tint-4: "#d3dbab"
  tint-4-ink: "#252c06"
  tint-5: "#a9d3d0"
  tint-5-ink: "#0b2927"
typography:
  display:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.005em"
  headline:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.2
  title:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 500
    lineHeight: 1.25
  plate-label:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.5
    letterSpacing: "0.12em"
  body:
    fontFamily: "Atkinson Hyperlegible Next Variable, Atkinson Hyperlegible Next, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "\"tnum\""
  label:
    fontFamily: "Atkinson Hyperlegible Next Variable, Atkinson Hyperlegible Next, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.5
  caption:
    fontFamily: "Atkinson Hyperlegible Next Variable, Atkinson Hyperlegible Next, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "\"tnum\""
rounded:
  sm: "4px"
  md: "8px"
  lg: "14px"
  pill: "999px"
spacing:
  "1": "0.25rem"
  "2": "0.5rem"
  "3": "0.75rem"
  "4": "1rem"
  "5": "1.5rem"
  "6": "2rem"
  "7": "3rem"
components:
  button-primary:
    backgroundColor: "{colors.brass}"
    textColor: "{colors.brass-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 1rem"
    height: "2.5rem"
  button-primary-hover:
    backgroundColor: "{colors.brass-strong}"
    textColor: "{colors.brass-ink}"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 1rem"
    height: "2.5rem"
  button-quiet-hover:
    backgroundColor: "{colors.surface-hover}"
  button-quiet-pressed:
    backgroundColor: "{colors.surface-sunk}"
  button-danger:
    backgroundColor: "{colors.signal-surface}"
    textColor: "{colors.signal-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 1rem"
    height: "2.5rem"
  button-danger-hover:
    backgroundColor: "{colors.signal}"
  button-board:
    backgroundColor: "{colors.board-raised}"
    textColor: "{colors.board-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 1rem"
    height: "2.5rem"
  button-board-hover:
    backgroundColor: "{colors.board-selected}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "0.5rem 0.75rem"
    height: "2.75rem"
  room-row:
    backgroundColor: "transparent"
    textColor: "{colors.board-ink}"
    rounded: "{rounded.md}"
    padding: "0.5rem"
  room-row-hover:
    backgroundColor: "{colors.board-raised}"
  room-row-selected:
    backgroundColor: "{colors.board-selected}"
  lamp-unread:
    backgroundColor: "{colors.lamp}"
    textColor: "{colors.lamp-ink}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    height: "1.375rem"
  lamp-mention:
    backgroundColor: "{colors.board-signal}"
    textColor: "{colors.lamp-ink}"
  avatar:
    backgroundColor: "{colors.tint-1}"
    textColor: "{colors.tint-1-ink}"
    rounded: "{rounded.md}"
    size: "2.25rem"
  composer:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "0.5rem"
  dialog:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "1.5rem"
    width: "30rem"
  day-plate:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.plate-label}"
    rounded: "{rounded.pill}"
    padding: "0.125rem 0.75rem"
  message-failed:
    backgroundColor: "{colors.signal-surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0.5rem"
---

# Design System: Conduit

## Overview

**Creative North Star: "The Dispatch Hall"**

Every message is a carrier sent down a tube. The client is a station hall in enamel: a cool pale ground where conversation is read and written, a deep tube-green destination board down the left where you choose where to send, and white enamel plates (the room header, the composer slot, dialogs, the sign-in card) that sit on top of the hall. The system's one job beyond legibility is to show where each carrier is and whether the line is clear, so state is drawn as physical furniture: lamps that glow, carrier capsules that fill, a line-status lamp at the foot of the board.

Density is that of a working tool used all day in one tab: compact rows on a 4px grid, fixed row furniture (every room row has the same plate, name, time, preview and lamp positions), and a reading measure of 72ch for message bodies. Two faces divide the work: a condensed signage face for anything you navigate by, a hyperlegible grotesk for anything you read or type, with tabular numerals throughout. Brass is scarce and therefore meaningful; signal red appears only where something needs a hand.

The night shift is the same hall in green-black enamel, where the brass lamps glow brighter. Light and dark are both first-class, swapped entirely through tokens (system preference by default, with an explicit light or dark override on the root). The world refuses the default bubble chat: no coloured speech bubbles, no grey ticks, no failures that vanish into a toast.

**Key Characteristics:**
- Tube-green destination board for navigation, pale enamel hall for reading, white enamel plates on top.
- Brass marks the primary action, lamps and links; red marks jams, errors, mentions and destruction.
- Condensed signage face (Barlow Condensed) for names, headings and plate labels; Atkinson Hyperlegible Next for messages and controls.
- Per-message carrier mark with four visible states; failures stay in place with their recovery actions.
- Round lamps with a 3px halo ring for every live state: unread, active room, line status, presence.
- Short ease-out motion (150 to 220ms), all of it zeroed under reduced motion.

## Colors

A cool green-grey enamel family carrying one warm metal (brass) and one alarm (signal red), with clear-green reserved for a healthy line.

### Primary
- **Station Brass** (`brass`): the fill of the one primary action per surface (Send, Sign in, Accept, dialog submit). Its pressed-hover partner **Burnished Brass** (`brass-strong`) also draws the in-tube and sent carrier, the typing dots, checked choices and the current-session badge outline.
- **Brass Script** (`brass-text`): brass darkened for text on light plates: links, link-buttons, thread reply counts, the current-session badge label.
- **Lamp Brass** (`lamp`, with `lamp-ink` numerals): the lit unread lamp, the active-room lamp, the connecting line lamp, and links and focus rings on the board.

### Secondary
- **Tube Green** (`board`): the destination board and the sign-in hall. It is also the light-theme focus colour, so focus reads as the board's ink on the pale hall. Its steps **Board Raised** (`board-raised`, hover rows, invite cards, board buttons, the sign-in foot strip) and **Board Selected** (`board-selected`, the open room's row) are tonal, not lighter tints of an accent.
- **Board Enamel** (`board-ink`) and **Board Chalk** (`board-ink-muted`): primary and secondary text on the board. **Board Rule** (`board-rule`) divides board regions.

### Tertiary
- **Signal Red** (`signal`, with `signal-surface` and `signal-ink`): jammed carriers, field and callout errors, the failed-message row, danger buttons and the danger settings section. On the board it becomes **Board Signal** (`board-signal`): jammed previews, mention lamps, reconnecting and error line lamps.
- **Line Clear** (`clear`, board form `board-clear`): only the healthy-line lamp and the online presence lamp.
- **Caution Enamel** (`caution-surface`, `caution-ink`): the reconnecting banner and the fill of your own reactions.

### Neutral
- **Hall Enamel** (`ground`): the page and timeline background.
- **Plate White** (`surface`): plates that sit on the hall: room header, composer, panels, dialogs, settings sections, day plates, reactions.
- **Sunk Enamel** (`surface-sunk`): recessed wells: reply quotes, media placeholders, pressed toggles, info callouts. **Hover Enamel** (`surface-hover`): row and quiet-button hover.
- **Hairline** (`rule`) for dividers and plate edges; **Strong Rule** (`rule-strong`) for input and quiet-button strokes, the delivered carrier and scrollbars.
- **Hall Ink** (`ink`), **Muted Ink** (`ink-muted`), **Faint Ink** (`ink-faint`): body text, secondary text, and timestamps and placeholders. All three pass WCAG AA on every hall and plate surface (enforced by `src/styles/contrast.test.ts`).
- **Name-plate tints** (`tint-0` to `tint-5`, each with an `-ink` partner): six enamel fills for avatar plates, chosen deterministically per user; every pair has a dark-theme value.
- **Halos** (`lamp-halo`, `signal-halo`, `clear-halo`): translucent rings around lit lamps. **Scrim** (`scrim`) behind modal dialogs. **Selection** (`selection`) is a pale brass.

### Named Rules
**The Brass Is Earned Rule.** Brass appears only where there is an action or a live state: the single primary button, lamps, links, carrier progress, your own marks. It is never a background area larger than a button and never decoration.

**The Red Means Hands Rule.** Signal red marks only what needs the person now: a jammed send, an error, a mention, a destructive action. A state that is merely inactive or offline is grey, not red.

**The Night Shift Rule.** Every colour token has a dark value in `tokens.css` (only `lamp-ink` stays dark in both shifts, because lamps stay bright), applied under `prefers-color-scheme: dark` unless the root says `data-theme="light"`, or forced by `data-theme="dark"`. Components never branch on theme and never carry a literal colour.

## Typography

**Display Font:** Barlow Condensed 500 and 600 (with Arial Narrow, sans-serif)
**Body Font:** Atkinson Hyperlegible Next Variable (with system-ui, sans-serif)

**Character:** Station signage over a reading face built for legibility. The condensed face is the voice of the building (where you are, which line, which day); the grotesk is the voice of the people in it.

### Hierarchy
- **Display** (Barlow Condensed 600, 1.75rem, 1.2): page titles on the sign-in plate, settings and account pages, and the welcome view.
- **Headline** (Barlow Condensed 600, 1.375rem, 1.2): the room header title, panel and dialog titles, the board wordmark scale on sign-in.
- **Title** (Barlow Condensed 500, 1.0625rem, 1.25; 600 when unread): room names on the board. Unread raises weight, never size.
- **Plate label** (Barlow Condensed 600, 0.875rem, 0.12em, uppercase): board section plates (Invites, Rooms), panel section plates, day plates, the line-status strip and the sign-in foot. The wordmark uses the same treatment at 1.125 to 1.375rem with 0.08 to 0.1em tracking.
- **Body** (Atkinson 400, 1rem, 1.5): message bodies, capped at 72ch, pre-wrapped.
- **Label** (Atkinson 600 to 700, 0.875rem): buttons, field labels, sender names (700), member names, secondary text and previews at 400.
- **Caption** (Atkinson 400, 0.75rem): timestamps, user IDs, badges, file sizes, edited marks.

### Named Rules
**The Two Faces Rule.** Things you navigate by (room names, headings, section and day plates, the wordmark) are set in Barlow Condensed; things you read or type (messages, previews, controls, fields) are set in Atkinson Hyperlegible Next. Never set message text in the condensed face.

**The Rank By Weight Rule.** Within a list, importance is shown by weight and case, not size: unread rooms go from 500 to 600 and their preview from chalk to full board ink.

**The Tabular Rule.** Tabular numerals are on for the whole document; times, counts and lamps never jitter.

**The Signage Label Rule.** Uppercase tracked plate labels name a section, a list, a day or the line's state, and sit at the head of that thing. They are never placed above a heading as a kicker.

## Layout

Two columns on desktop: an 18.5rem destination board and a fluid main column, filling the viewport height (`100dvh`) with each region scrolling independently. A side panel (members, threads) opens as a third column between 17rem and 24rem; below 1180px it overlays the room from the right with dialog-level shadow. Below 760px the shell is one column: the board is the home view and the room replaces it, with a back link in the room header and header button labels collapsing to icons.

The timeline is a centered column up to 56rem wide, its messages on a two-column grid (a 2.25rem gutter for the avatar plate or hover timestamp, then the body). Consecutive messages from one sender group under one header with 1px rhythm; a new sender gets 0.5rem. Day plates break the run with 1.5rem above. The timeline is anchored to the composer: content pushes up from the bottom, so a short room reads at the slot, not at the top of an empty hall.

Spacing is a 4px-based scale (0.25rem to 3rem, steps 1 to 7). Rows pad at step 2, plates at step 5, pages at step 6. Hit targets are at least 2rem (small buttons, action strip), 2.25rem for icon buttons, 2.5rem for buttons and 2.75rem for inputs.

### Named Rules
**The Anchored Timeline Rule.** The newest message always sits directly above the composer; empty space collects above the history, never between the last message and the slot.

**The Fixed Furniture Rule.** Every room row has the same slots in the same places: name plate, room name, time, preview, and a right-hand lamp position for unread, active or carrier state. Content changes; furniture does not move.

## Elevation & Depth

A hybrid: the hall and the board are flat and separated by tone and hairlines; only plates that sit on top of the hall cast a soft, low, cool-inked shadow. Depth means "this is lifted off the wall", never "this is important".

### Shadow Vocabulary
- **Plate** (`box-shadow: 0 1px 2px rgb(19 32 28 / 0.08), 0 8px 24px -12px rgb(19 32 28 / 0.25)`): the composer slot, the sign-in plate, the hover action strip on a message, the jump-to-latest button, the skip link.
- **Dialog** (`box-shadow: 0 2px 6px rgb(19 32 28 / 0.12), 0 24px 48px -16px rgb(19 32 28 / 0.4)`): modal dialogs and the overlaid side panel on narrower screens.
- **Pressed brass** (`box-shadow: inset 0 -2px 0 rgb(0 0 0 / 0.12)`): the bottom lip on the primary button.
- **Lamp halo** (`box-shadow: 0 0 0 3px` a halo token; 2px for presence): the glow ring around a lit lamp.

Dark theme deepens both plate and dialog shadows to black at 0.4 to 0.8 opacity.

### Named Rules
**The Lifted Plates Rule.** Shadows belong only to things that sit over the hall (composer, dialogs, overlays, the floating action strip). Rows, cards on the board, settings sections and the timeline stay flat and use tone or a hairline.

## Shapes

Enamel plates with softly rounded corners: 4px for small inline wells and compact avatars, 8px for buttons, inputs, rows, avatar plates and cards, 14px for the large plates (composer, dialogs, the sign-in plate, settings sections). Pills (999px) are reserved for lamps, day plates, reactions and badges. Lamps and presence dots are circles. Borders are 1px hairlines; a selected choice or invalid field doubles its edge with a 1px inset ring rather than a thicker border.

The signature silhouette is the carrier capsule: a rounded tube section with a brass capsule inside (the mark), scaled down to an 18 by 10 capsule beside each of your own messages.

## Components

### Buttons
Solid and tactile, with a 1px press-down on activation.
- **Shape:** gently rounded (8px), 2.5rem tall, 1rem side padding; small variant 2rem tall.
- **Primary:** brass fill with dark brass-ink label at 600 weight, plus a 2px inset lower lip. One per surface.
- **Hover / Focus:** hover steps to burnished brass over 150ms ease-out; focus is the global 2px focus outline at 2px offset. Disabled sits at 0.55 opacity; busy at 0.8 with a progress cursor and `aria-busy`.
- **Quiet:** transparent with a strong-rule stroke; hover fills with hover enamel; a pressed toggle (`aria-pressed`) sinks to sunk enamel with a muted-ink stroke.
- **Danger:** signal surface with signal ink and a signal stroke; hover fills solid signal red with white text.
- **Board:** raised board fill, board ink and a board-rule stroke, for New room, Join and invite actions on the board.
- **Icon button:** 2.25rem square, borderless, muted ink, hover enamel on hover. Icons are Lucide SVGs at 14 to 20px, stroke 2.
- **Link button:** brass script, 600 weight, 1px underline offset 0.18em; on the board it uses lamp brass, in failure lines signal ink.

### Inputs / Fields
- **Style:** plate-white fill, 1px strong-rule stroke, 8px radius, 2.75rem minimum height; label above in 600 weight at 0.875rem, hint below in muted ink.
- **Focus:** stroke and a 2px outline both switch to the focus colour (tube green by day, pale tube green by night), outline at zero offset.
- **Error / Disabled:** invalid fields gain a signal stroke plus a 1px inset signal ring, with a 600-weight signal error line below. Choice cards (radio rows) take a burnished-brass stroke and inset ring when checked.

### Navigation (the destination board)
- **Board:** tube-green column with the mark and wordmark at the head, New room and Join board buttons, Invites and Rooms sections under plate labels with counts, and a foot holding the line-status strip and the account row.
- **Room row:** fixed furniture on an 8px-rounded row; hover lifts to board raised, the open room sits on board selected and shows the brass active lamp (0.5rem circle with halo) when it has no unread count. Focus on the board is a 2px lamp-brass outline inset by 2px.
- **Invite card:** board-raised card with a board-rule edge, Accept as the brass primary and Decline as a board button.
- **Mobile:** the board becomes the full home screen; selecting a room replaces it.

### Lamps
- **Unread lamp:** a pill at least 1.375rem, lamp brass with dark numerals at 700 weight, ringed by a 3px lamp halo. Mentions switch to board signal with a signal halo.
- **Line-status lamp:** 0.625rem circle beside the plate label: clear green with halo when live, lamp brass when connecting, board signal when reconnecting (blinking at 1.4s, stopped under reduced motion) or in error, chalk when idle. The sign-in foot carries the same lamp beside "Line to" and the server address.
- **Presence lamp:** 0.5rem circle: clear with a 2px halo online, brass when away, strong rule otherwise.

### Carrier Mark (signature)
The per-message status capsule beside each of your own messages, also shown on the board row for the room's latest own send.
- **Queued:** hollow capsule in faint ink.
- **In the tube:** burnished-brass shell whose fill travels left to right on a 1.1s ease-out loop; frozen half-full under reduced motion.
- **Sent:** solid burnished brass. **Delivered:** solid strong rule, receding once the job is done.
- **Jammed:** signal-red capsule cut by a notch, the whole message row tinted signal surface, with "Not sent" and the reason in signal ink and in-place Retry and Delete link buttons. The board row shows the jam too, in board signal, so a failure is visible from any room.
- Each state carries a visually hidden label and a title for assistive tech.

### Messages and the timeline
- **Message row:** two-column grid on an 8px-rounded row; hover enamel on hover; 2px focus outline inset. Sender in 700 weight label size; grouped follow-ups show their timestamp in the gutter only on hover or focus.
- **Action strip:** a small floating plate (plate shadow, hairline edge) at the row's top right with 2rem icon buttons, fading in over 150ms on hover or focus-within; on touch devices it sits statically under the message.
- **Day plate:** a centered pill in plate label type on plate white, with hairlines running to both edges.
- **State lines:** room state changes in muted small text aligned to the body column, collapsible into a group with a rotating chevron.
- **Relations:** reply quotes are sunk wells with a bold sender; thread summaries are hairline plates with a brass-script count; reactions are pills, your own in caution enamel with a burnished-brass edge; read receipts are tiny 1.125rem avatar plates.

### Composer (the dispatch slot)
A plate-white slot with a 14px radius, strong-rule stroke and plate shadow, anchored at the foot of the room. The textarea is borderless inside it and grows to 12rem; the stroke turns to the focus colour when anything inside has focus. Attach is an icon button on the left, Send the brass primary on the right. Reply and edit context sits in a hairline-divided strip above the input.

### Dialogs and plates
- **Dialog:** a white enamel plate, 30rem wide (38rem for directory), 14px radius, dialog shadow over the scrim, entering with a 220ms rise (6px and 0.99 scale) that is removed under reduced motion. Title in headline type, description in muted ink, actions right-aligned with the primary last.
- **Sign-in:** a 26rem enamel plate on the full tube-green board, holding the mark and wordmark, a display-type title and the form, with a board-raised foot strip naming the line it will connect to.
- **Settings sections:** flat plate-white sections with a hairline edge and 14px radius; the danger section takes a signal edge. Facts render as a two-column definition list.

### Avatars (name plates)
Square enamel plates (2.25rem, 8px radius) with the initial in the condensed face at 600, filled from one of six tints by user; 1.75rem and 1.125rem variants for the member panel and read receipts.

## Do's and Don'ts

### Do:
- **Do** take every colour, size, space, radius, shadow and duration from `tokens.css`; add a token (with a dark value) before using a new one.
- **Do** keep exactly one brass primary action per surface, and show every send's carrier state beside the message.
- **Do** keep a failed send in place in the timeline and on its board row, with Retry and Delete beside it.
- **Do** mark live state with a round lamp and its halo ring, including the open room.
- **Do** use the global 2px focus outline (tube green by day, pale tube green by night, lamp brass on the board) and keep every text pair at WCAG AA in both themes.
- **Do** keep motion between 150 and 220ms with the ease-out curve, and let it fall to zero under `prefers-reduced-motion`.
- **Do** announce new messages, send failures and line changes through live regions, since the visual state is not enough on its own.

### Don't:
- **Don't** render messages as coloured speech bubbles or report send state with grey ticks.
- **Don't** mark the selected room with a coloured side stripe; the active room gets a lamp.
- **Don't** report a failed send only in a toast or banner that can disappear.
- **Don't** use brass or signal red as decoration, large fills or emphasis for ordinary text.
- **Don't** set message or input text in the condensed signage face.
- **Don't** place an uppercase tracked label above a heading as a kicker.
- **Don't** give flat hall furniture (rows, board cards, settings sections) a drop shadow.
