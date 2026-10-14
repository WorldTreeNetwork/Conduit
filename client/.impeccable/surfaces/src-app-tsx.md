---
version: 1
slug: "src-app-tsx"
primary_target: "src/App.tsx"
related_targets: []
---

# Surface brief: Conduit web client (app shell, sign-in, rooms, timeline)

Mode: Operate. Audience: people chatting on a Conduit homeserver in a long-lived browser tab; operators verifying the server. Task: sign in, scan rooms, read/write, manage membership. Constraints: WCAG AA, keyboard-first, light + dark, deterministic test hooks. Unattended run: decision page not served (no one to answer); assigned direction built code-led.

Grounded list (resonance order): 1 Swiss typographic signage grid; 2 radio operator's logbook; 3 telephone switchboard panel; 4 mailroom pigeonhole rack; 5 engineering graph notebook; 6 pneumatic-tube dispatch hall; 7 IRC terminal. Assigned: 6.

Challenger verdicts: timetable slide rack declined (kept: rank by weight/case, not size); character catalog declined (kept: every room row has fixed furniture); warm consumer app competitive on clarity, not chosen (kept: the saturated colour appears only where an action exists); transit diagram declined (kept: explicit service-state vocabulary for sync health); botanical folio declined; datamatics declined (kept: tabular numerals for times and counts).

## Direction contract

THESIS: Every message is a carrier sent down a tube. The client always shows where each carrier is (queued, in the tube, delivered, jammed) and whether the line is clear, refusing the default bubble chat with grey ticks and hidden failures.

OWN-WORLD: Station enamel. Cool pale enamel ground, a deep tube-green destination board for navigation, white enamel plates for dialogs, brass only for lamps (unread, active) and the one primary action, signal red for jams. Condensed signage face for plates and headings, hyperlegible grotesk for messages, tabular numerals. Night shift: green-black enamel, brass lamps glow.

STORY: The person sees their destinations, which ones have mail waiting, reads and replies, and trusts that nothing they send is silently lost.

FIRST VIEWPORT: Left destination board (room plates with brass unread lamps, invites on top, line-status strip at the foot). Right: room header plate, timeline grouped by sender with day plates, dispatch slot composer at the bottom with brass Send.

FORM: Pneumatic-tube dispatch hall, position 6 of 7, seed key bfaff76d. Signature interaction: the carrier status mark beside own messages (hollow queued, filling in-tube, solid delivered, notched red jammed with Retry/Discard). Motion 150-220ms ease-out, none under reduced motion. Raises: weight/case rank (timetable), fixed row furniture (catalog), service-state vocabulary (transit), tabular numerals (datamatics).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
