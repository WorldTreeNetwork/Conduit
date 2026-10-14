# Product

<!-- impeccable:product-schema 1 -->

> Inferred record. Written by an unattended agent lane from the explicit
> task brief (bead conduit-y99.9) and repository evidence; no interview
> round was possible. Every fact below is labelled *(brief)* or
> *(repo)*; nothing here was confirmed by a human answer.

## Platform

web

## Stack

React 18 + Vite + TypeScript, pnpm; framework-free Matrix protocol core
in `client/src/core/`. *(brief: decided by the project owner, not to be
relitigated)*

## Users

People who run or join a Conduit homeserver and want to talk in Matrix
rooms from a browser: sign in, see their rooms, read and write messages,
invite others, manage membership. *(brief)* Operators and developers also
use the client to verify the homeserver end to end. *(repo)*

## Product Purpose

The first-party Matrix client for Conduit: a usable, accessible chat
client that speaks the stable Matrix Client-Server API against any
compliant homeserver, and that doubles as the unattended verification
harness for Conduit's client-facing behaviour. Success: a person can
register, create a room, invite someone, chat both ways, scroll history,
recover from a failed send and sign out without confusion, and an
automated run can prove the same. *(brief)*

## Positioning

Own protocol core (no matrix-js-sdk), deterministic automation hooks and
real-server e2e as first-class features; the client is how Conduit proves
its own spec compliance. *(brief)*

## Operating Context

Long-lived browser tab, used throughout a working day on desktop, also
on narrow screens. Network drops and server restarts happen; the client
must say so and recover. *(brief: offline/reconnecting banner, retries)*

## Capabilities and Constraints

Phase 1: password login and registration (UIA m.login.dummy), room list
with unread counts and previews, timeline with pagination, composer with
local echo and retry, create/join/invite/accept/decline/leave, member
list, display name, logout, settings stub. Later: media, typing,
receipts, presence, relations, device management, room settings,
directory, E2EE via matrix-sdk-crypto-wasm. *(brief)*

## Brand Commitments

Name: Conduit. No logo or brand assets exist in the repository. *(repo)*

## Evidence on Hand

None. No screenshots, testimonials or brand material exist; none may be
fabricated. *(repo)*

## Product Principles

1. Messages first: chrome recedes behind conversation.
2. State is always visible: sync health, send status and errors are
   never hidden.
3. Every failure has a recovery action in place.
4. Keyboard and screen-reader users get the same client.

## Accessibility & Inclusion

WCAG 2.2 AA: contrast, keyboard navigation through room list and
timeline, focus management on route changes, aria-live for new messages
and errors, reduced-motion respect. Automated axe checks with zero
serious violations. *(brief)*
