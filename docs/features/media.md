# Media Repository

**Spec reference:** [Content Repository API] (v1.19), [federation content repository]
**Default:** on
**Depends on:** [`client-server-api`](client-server-api.md), [`storage`](storage.md)

[Content Repository API]: https://spec.matrix.org/v1.19/client-server-api/#content-repository
[federation content repository]: https://spec.matrix.org/v1.19/server-server-api/#content-repository

## What this is

How Matrix moves bytes that aren't text — images, files, voice
messages, sticker packs. The media repo is its own subdomain of the
spec, distinct from event sending.

## Endpoints

All client routes live in `conduit-server/src/api/client/media.rs`
(`media::router()`, merged once in `main.rs`); previews in
`media_preview.rs`; the SSRF-safe fetcher in `safe_fetch.rs`.

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /_matrix/media/v3/upload` | token | `?filename=`, `Content-Type` default `application/octet-stream` |
| `POST /_matrix/media/v1/create` | token | async upload reservation, `unused_expires_at` |
| `PUT  /_matrix/media/v3/upload/{serverName}/{mediaId}` | token | completes a reservation |
| `GET  /_matrix/client/v1/media/config` · `/_matrix/media/v3/config` | token | identical bodies |
| `GET  /_matrix/client/v1/media/download/{serverName}/{mediaId}[/{fileName}]` | token | `timeout_ms` |
| `GET  /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}` | token | `width`,`height`,`method`,`animated`,`timeout_ms` |
| `GET  /_matrix/client/v1/media/preview_url` · `/_matrix/media/v3/preview_url` | token | `url`, `ts` |
| `GET  /_matrix/media/v3/download/…` · `/_matrix/media/v3/thumbnail/…` | none | deprecated, **frozen**; `allow_remote`, `allow_redirect`, `timeout_ms` |
| `GET  /_matrix/federation/v1/media/download/{mediaId}` · `/thumbnail/{mediaId}` | X-Matrix | see gap below |

## Behaviour

- **Content-Type** is stored exactly as uploaded; absent means
  `application/octet-stream` (no sniffing — the spec bounds "reasonable"
  deviations and sniffing is not one).
- **Content-Disposition**: `inline` only for the spec's inline-safe list
  (`text/plain`, `text/css`, `text/csv`, JSON, common image/video/audio
  types), else `attachment`. The `filename` given at upload (or the path
  override, or the remote server's) is reproduced exactly — quoted-string
  for printable ASCII, RFC 8187 `filename*=utf-8''…` otherwise — and
  omitted when none was given. Thumbnails are always `inline; filename="thumbnail.png"`.
- Every body carries the spec's recommended
  `Content-Security-Policy: sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; object-src 'self';`,
  `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: cross-origin`.
- **mxc sanitisation**: media IDs must match `[A-Za-z0-9_-]+` (else 404);
  server names must be valid server names (else 400 `M_INVALID_PARAM`).
- **Freeze** (v1.11 warning box): the `media.unauthenticated_access`
  column (migration 0040) is true for rows that existed before the
  freeze and false for everything stored afterwards, including remote
  cache fills. Deprecated endpoints return 404 `M_NOT_FOUND` for frozen
  media and never trigger remote fetches.
  `CONDUIT_MEDIA_FREEZE_UNAUTHENTICATED=0` disables the freeze; media stored
  while it is disabled stays reachable if it is re-enabled.
- **Async upload**: `POST /media/v1/create` reserves an ID in
  `media_pending` (24 h default, `CONDUIT_MEDIA_UNUSED_EXPIRATION_MS`);
  at most `CONDUIT_MEDIA_MAX_PENDING_UPLOADS` (5) unexpired reservations
  per user, else 429 `M_LIMIT_EXCEEDED` with `retry_after_ms`. `PUT`
  by a non-creator is 403 `M_FORBIDDEN`, to existing content 409
  `M_CANNOT_OVERWRITE_MEDIA`, to unknown/expired IDs 404. Completion
  consumes the reservation and inserts the media row in one transaction.
  Downloads/thumbnails of pending media wait up to `timeout_ms`
  (default 20 s, capped 60 s), woken on upload completion, then 504
  `M_NOT_YET_UPLOADED`.
- **Limits**: uploads over `CONDUIT_MEDIA_MAX_UPLOAD_BYTES` (50 MiB) are
  413 `M_TOO_LARGE` (the handler streams the body itself; axum's 2 MiB
  default is disabled on upload routes). Remote content over the limit
  is 502 `M_TOO_LARGE`. Images over `CONDUIT_MEDIA_MAX_THUMBNAIL_PIXELS`
  (32 Mpx) are not thumbnailed: 413 (local) / 502 (remote) `M_TOO_LARGE`.
- **Thumbnails**: never upscaled; content no larger than the request is
  returned as-is. `scale` keeps aspect ratio and is never smaller than
  the requested box unless the source is; `crop` returns exactly the
  requested size (or the largest centred region with that aspect for a
  smaller source). JPEG sources produce JPEG, everything else PNG.
  `animated=true` may return a small animated original; otherwise the
  output is static. Missing `width`/`height` → 400 `M_MISSING_PARAM`;
  bad values/method/animated → 400 `M_INVALID_PARAM`; non-images → 400
  `M_UNKNOWN`. Generated thumbnails are cached per (w, h, method).
- **Remote media**: fetched over federation
  (`/_matrix/federation/v1/media/download`, multipart/mixed parsed; raw
  bodies tolerated; `Location` parts fetched through the SSRF-safe
  fetcher; `M_UNRECOGNIZED` falls back to the legacy media path), cached
  with the remote filename. 404 `M_NOT_FOUND` when federation is disabled
  (`CONDUIT_FEDERATION=0`) or `allow_remote=false`.
- **URL previews**: see below.

## URL previews and SSRF

`safe_fetch::fetch` is the only way the server fetches user-chosen URLs:

1. Only `http`/`https`. IP-literal hosts (including WHATWG forms like
   `2130706433` or `0x7f.1`) are classified directly.
2. Hostnames are resolved by the server; if **any** address is denied the
   request is refused (403 `M_FORBIDDEN`). The reqwest client uses a
   resolver that re-applies the check, so DNS rebinding cannot swap in an
   internal address between check and connect; the connected peer
   address is checked again.
3. Denied: 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12,
   192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15,
   198.51.100/24, 203.0.113/24, 224/4, 240/4; `::`, `::1`, `::/96`,
   `::ffff:0:0/96` (all IPv4-mapped), NAT64/6to4 embedding a denied IPv4,
   `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `fc00::/7`,
   `fe80::/10`, `fec0::/10`, `ff00::/8`.
   `CONDUIT_URL_PREVIEW_IP_ALLOWLIST` (CIDRs) exempts ranges; an IPv4
   entry never admits its IPv4-mapped IPv6 spelling.
4. Redirects are followed manually (max 5), each hop re-validated.
5. Body capped while streaming (`CONDUIT_URL_PREVIEW_MAX_BYTES`, 10 MiB →
   502 `M_TOO_LARGE`), one deadline for the whole fetch
   (`CONDUIT_URL_PREVIEW_TIMEOUT_MS`, 10 s → 504), proxies ignored.

HTML is reduced to `og:*` properties (first value wins; `<title>` and
`meta name=description` fallbacks; entities decoded; ≤ 64 keys, ≤ 1000
chars each). `og:image` is resolved against the final URL, fetched under
the same policy, and re-hosted as local media: `og:image` becomes the
`mxc://` URI, with `og:image:type`, `og:image:width/height` (from the
decoded image) and `matrix:image:size`. Unfetchable images drop all
`og:image*` keys. A URL that is an image previews as that image; other
types yield `{}`. Results are cached in `url_previews`
(`CONDUIT_URL_PREVIEW_CACHE_MS`, 1 h), one row per fetch: `ts` returns the
newest preview fetched at or before `ts`, else a newer one.
`CONDUIT_URL_PREVIEW=0` disables previews (404 `M_UNRECOGNIZED`).

## Tests

- Unit: `media.rs` (inline list, disposition encoding round trip,
  mxc validation, thumbnail sizing/animation, multipart parsing),
  `safe_fetch.rs` (every denied range, allowlist, literal/resolved hosts
  refused before connecting), `media_preview.rs` (OG parsing).
- In-process: `conduit-server/tests/media.rs` incl. a mock origin server
  serving multipart/mixed federation media (fetch, cache, no refetch,
  remote filename, freeze, 404, 502 `M_TOO_LARGE`).
- Production binary + Postgres: `conduit-server/tests/production_media.rs`.

## Known gaps

- Federation media endpoints still answer raw bytes instead of
  `multipart/mixed` and do not wait for pending uploads
  (`conduit-y99.21.1`, federation lane).
- Animated thumbnail generation and non-UTF-8 previews (`conduit-y99.21.2`).
- Blob GC for thumbnails/admin deletes; preview-image retention
  (`conduit-y99.21.3`). Per-user quotas (`conduit-38v`).
