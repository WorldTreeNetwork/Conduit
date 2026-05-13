# E07 — Media Repository

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/media.md](../docs/features/media.md)
**Depends on:** E04
**Blocks:** —

## Scope

Accept uploads, mint `mxc://` URIs, serve downloads + thumbnails,
fetch remote media on demand, enforce safety headers. Authenticated
media endpoints are the target; legacy unauth endpoints kept for
compatibility.

## "Done" looks like

- An Element client uploads an image and other clients render the
  thumbnail and the full image.
- Remote media (a `mxc://other.example/...`) is fetched and cached.

## Stories

- [ ] **E07-1**: Blob storage backend (filesystem sharded by hash).
- [ ] **E07-2**: Media metadata schema in storage.
- [ ] **E07-3**: `POST /_matrix/media/v3/upload`.
- [ ] **E07-4**: `GET /_matrix/media/v3/download/{server}/{mediaId}`
      (legacy unauth).
- [ ] **E07-5**: `GET /_matrix/client/v1/media/download/...`
      (authenticated).
- [ ] **E07-6**: Thumbnail generator (pull in `image` crate).
- [ ] **E07-7**: `GET /_matrix/media/v3/thumbnail/...` (legacy) +
      `/_matrix/client/v1/media/thumbnail/...` (authenticated).
- [ ] **E07-8**: Federation media fetch path (cache remote blobs).
- [ ] **E07-9**: Safe response headers (`Content-Disposition`,
      sandbox CSP, `nosniff`, size limits).
- [ ] **E07-10**: `GET /_matrix/media/v3/config` (upload size limit).
- [ ] **E07-11**: Retention policy for cached remote media (TTL).

## Open questions

- Generate thumbnails on upload (eager) or on first request (lazy)?
  Lazy saves CPU but slows first render.

## Risks

- Media is the #1 source of storage growth and #1 abuse vector.
  Quotas + retention on day one, not later.
- Untrusted blobs served at user-controlled paths — sandbox CSP is
  not optional.
