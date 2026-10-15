<script lang="ts">
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import { describeError, type MatrixClient } from '#lib/session.js';
 let { client, signOut }: { client: MatrixClient; signOut: () => void } = $props();
 let password = $state(''), error = $state(''), pending = $state(false);
 async function submit() { if (!password || pending) return; pending = true; error = ''; try { await client.reauthenticate(password); } catch (e) { error = describeError(e); } finally { pending = false; password = ''; } }
</script>
<main class="reauth"><div class="rest-stack"><h1>Your session expired</h1><p>Sign in again as <strong>{client.userId}</strong> to continue on this device. Your rooms and unsent messages are kept.</p><form class="rest-stack" onsubmit={e => { e.preventDefault(); void submit(); }}><label for="reauth-password">Password</label><Input id="reauth-password" type="password" autocomplete="current-password" bind:value={password} required disabled={pending} />{#if error}<p class="rest-error" role="alert">{error}</p>{/if}<Button type="submit" disabled={pending || !password}>{pending ? 'Signing in…' : 'Continue'}</Button></form><Button variant="outline" onclick={signOut}>Sign out instead</Button></div></main>
<style>.reauth { min-height:100dvh; display:grid; place-items:center; padding:1.5rem; } .reauth > div { max-width:28rem; padding:1.5rem; border:1px solid var(--color-rule); background:var(--color-surface); border-radius:var(--radius-lg); } h1 { font-size:var(--text-2xl); }</style>
