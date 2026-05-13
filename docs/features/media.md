# Media Repository

**Spec reference:** [Content Repository API]
**Default:** on
**Depends on:** [`client-server-api`](client-server-api.md), [`storage`](storage.md)

[Content Repository API]: https://spec.matrix.org/latest/client-server-api/#content-repository

## What this is

How Matrix moves bytes that aren't text — images, files, voice
messages, sticker packs. The media repo is its own subdomain of the
spec, distinct from event sending.

## What the homeserver needs to do

- Accept uploads, mint a `mxc://server/mediaId` URI, store the blob.
- Serve downloads by `mediaId`.
- Serve thumbnails: generate them on demand (or eagerly) at requested
  dimensions.
- Forward requests for **remote** media: if the URI is for another
  server, fetch (and cache) from there.
- Implement the authenticated-media endpoints (newer spec) — old
  unauthenticated `/download` and `/thumbnail` are deprecated.

## Endpoints

| Endpoint                                                               | Auth          |
|------------------------------------------------------------------------|---------------|
| `POST /_matrix/media/v3/upload`                                        | client token  |
| `GET  /_matrix/media/v3/download/{serverName}/{mediaId}`               | unauth (legacy)|
| `GET  /_matrix/media/v3/thumbnail/{serverName}/{mediaId}`              | unauth (legacy)|
| `GET  /_matrix/client/v1/media/download/{serverName}/{mediaId}`        | client token  |
| `GET  /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}`       | client token  |
| `GET  /_matrix/federation/v1/media/download/{mediaId}`                 | X-Matrix sig  |
| `GET  /_matrix/media/v3/config`                                        | client token  |

## Implementation approach

1. Store blobs on the local filesystem in a sharded directory layout
   (`media/ab/cd/abcd1234...`) or in object storage. The `mediaId` is
   yours to mint — random 32-byte base64 is fine.
2. Thumbnailing: use an image library (e.g. the `image` crate).
   Generate small thumbnails on upload; generate larger ones on demand.
3. Don't trust uploaded `Content-Type` — sniff it. Reject unsafe
   types (HTML, SVG with scripts) for browser-loaded download paths.
4. Set strict response headers on `download` responses:
   `Content-Disposition: attachment; filename="..."`,
   `Content-Security-Policy: sandbox`,
   `X-Content-Type-Options: nosniff`.

## Gotchas

- Media is the highest-risk surface for storage growth. Implement a
  retention policy from day one (TTL on remote-cached media; quota
  per user).
- Federation media fetch can be a vector for unbounded blob downloads
  from hostile servers. Set hard size limits and timeouts.
- Authenticated media changed the URL shape. Clients negotiate which
  endpoint to use via `/versions` and capability flags.
- Thumbnail generation is CPU-heavy; run it in a worker pool so
  uploads don't block.
