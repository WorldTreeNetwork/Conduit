<script lang="ts">
 import type { MatrixClient } from '#lib/session.js';
 let { client, userId, version }: { client: MatrixClient; userId: string; version: number } = $props();
 const state = $derived.by(() => { version; return client.presence.get(userId)?.presence; });
 const label = $derived(state === 'online' ? 'Online' : state === 'unavailable' ? 'Away' : state === 'offline' ? 'Offline' : '');
</script>
{#if label}<span class="presence" data-testid="presence" data-presence={state}><span class="lamp" aria-hidden="true"></span>{label}</span>{/if}
<style>
 .presence { display:inline-flex; align-items:center; gap:.35rem; font-size:var(--text-xs); color:var(--color-ink-muted); }
 .lamp { width:.5rem; height:.5rem; border-radius:50%; background:var(--color-ink-faint); }
 [data-presence=online] .lamp { background:var(--color-clear); } [data-presence=unavailable] .lamp { background:var(--color-brass-text); }
</style>
