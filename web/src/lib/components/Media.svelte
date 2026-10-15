<script lang="ts">
 import { describeError, formatBytes, type JsonObject, type MatrixClient } from '#lib/session.js';
 import { Button } from '#lib/components/ui/button/index.js';
 let { client, content, localUrl }: { client: MatrixClient; content: JsonObject; localUrl?: string } = $props();
 let url = $state(''), error = $state(''), busy = $state(false);
 const image = $derived(content.msgtype === 'm.image');
 const name = $derived(String(content.filename || content.body || (image ? 'Image' : 'file')));
 const mxc = $derived(typeof content.url === 'string' ? content.url : undefined);
 const info = $derived((content.info ?? {}) as JsonObject);
 const size = $derived.by(() => {
  const w = typeof info.w === 'number' && Number.isFinite(info.w) && info.w > 0 ? info.w : 320;
  const h = typeof info.h === 'number' && Number.isFinite(info.h) && info.h > 0 ? info.h : 240;
  const scale = Math.min(1, 320 / w, 240 / h);
  // A 1px source is still an open-image target. Match the current client's 44px floor.
  return { width: Math.max(44, Math.round(w * scale)), height: Math.max(44, Math.round(h * scale)) };
 });
 $effect(() => {
  const uri = mxc, local = localUrl, dimensions = size;
  let cancelled = false;
  url = ''; error = '';
  if (image && !local && uri) void client.mediaUrl(uri, { width: Math.min(640, dimensions.width * 2), height: Math.min(480, dimensions.height * 2) })
   .then(value => { if (!cancelled) url = value; }).catch(e => { if (!cancelled) error = describeError(e); });
  return () => { cancelled = true; };
 });
 async function download() {
  if (!mxc || busy) return;
  busy = true; error = '';
  try {
   const full = await client.mediaUrl(mxc);
   if (image) window.open(full, '_blank', 'noopener');
   else { const a = document.createElement('a'); a.href = full; a.download = name; a.click(); }
  } catch (e) { error = describeError(e); }
  finally { busy = false; }
 }
</script>
{#if image}
 <button type="button" class="image-preview" style:width={`${size.width}px`} style:aspect-ratio={`${size.width}/${size.height}`} aria-label={`Open image ${name}`} disabled={busy || (!mxc && !localUrl)} onclick={() => void download()} data-testid="media-image">
  {#if localUrl || url}<img src={localUrl || url} alt={name} width={size.width} height={size.height} onerror={() => { error = "Couldn't display the image."; }} data-testid="media-image-img" />{:else}<span>{error ? 'Image unavailable' : 'Loading image…'}</span>{/if}
 </button>
{:else}
 <div class="file-card"><span>{name}<small>{formatBytes(typeof info.size === 'number' ? info.size : NaN)}</small></span>{#if mxc}<Button variant="outline" disabled={busy} aria-label={`Download ${name}`} onclick={() => void download()}>Download</Button>{/if}</div>
{/if}
{#if error}<p class="rest-error" role="status" data-testid="media-error">Couldn't load {image ? 'the image' : 'the file'}. {error}</p>{/if}
<style>
 .image-preview { display:block; max-width:100%; background:var(--color-surface-sunk); border:1px solid var(--color-rule); border-radius:var(--radius-md); overflow:hidden; margin:.5rem 0; cursor:pointer; }
 .image-preview img { width:100%; height:100%; object-fit:contain; }
 .image-preview:focus-visible { outline:2px solid var(--color-focus); outline-offset:3px; }
 .file-card { display:flex; gap:1rem; align-items:center; padding:.75rem; border:1px solid var(--color-rule); border-radius:var(--radius-md); margin:.5rem 0; }
 .file-card span { min-width:0; overflow-wrap:anywhere; flex:1; } small { display:block; color:var(--color-ink-muted); }
</style>
