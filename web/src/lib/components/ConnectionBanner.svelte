<script lang="ts">
 import { Button } from '#lib/components/ui/button/index.js';
 import type { MatrixClient } from '#lib/session.js';
 let { client, version, line = false }: { client: MatrixClient; version: number; line?: boolean } = $props();
 const health = $derived.by(() => { version; return client.syncHealth; });
 const labels = { stopped: 'Offline', connecting: 'Connecting', live: 'Line clear', reconnecting: 'Line down', error: 'Signed out' };
 let now = $state(Date.now());
 $effect(() => { if (health.state !== 'reconnecting') return; now = Date.now(); const timer = setInterval(() => { now = Date.now(); }, 1000); return () => clearInterval(timer); });
</script>
{#if line}
 <p class="line-status" data-testid="sync-status" data-state={health.state}><span aria-hidden="true">●</span> {labels[health.state]}</p>
{:else}
 <div role="status" aria-live="polite" data-testid="connection-banner-region">
  {#if health.state === 'reconnecting'}<div class="connection-banner" data-testid="connection-banner"><p><strong>Reconnecting.</strong> {health.lastError ?? "The server isn't answering."} {#if health.nextRetryAt && health.nextRetryAt > now}Trying again in {Math.ceil((health.nextRetryAt - now) / 1000)}s. {/if}Anything that fails to send stays here for you to retry.</p><Button variant="outline" onclick={() => client.sync.retryNow()} data-testid="retry-sync">Retry now</Button></div>{/if}
 </div>
{/if}
<style>
 .line-status { color:var(--color-board-ink-muted); font-size:var(--text-sm); margin-bottom:.75rem; }
 .line-status span { color:var(--color-board-signal); } [data-state=live] span { color:var(--color-board-clear); }
 .connection-banner { display:flex; align-items:center; flex-wrap:wrap; gap:.75rem; padding:1rem; background:var(--color-caution-surface); color:var(--color-caution-ink); border-bottom:1px solid var(--color-rule); font-size:var(--text-sm); } p { flex:1; min-width:12rem; }
</style>
