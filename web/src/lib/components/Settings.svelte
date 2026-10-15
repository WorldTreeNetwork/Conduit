<script lang="ts">
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import { describeError, type MatrixClient } from '#lib/session.js';
 import { loadTheme, saveTheme, type ThemeChoice } from '#lib/theme.js';
 import AccountSettings from './AccountSettings.svelte';
 let { client, onProfileChanged, signOut, onDeactivated }: { client: MatrixClient; onProfileChanged: (name: string) => void; signOut: () => void; onDeactivated: () => void } = $props();
 let name = $state(''), loading = $state(true), loadError = $state(''), saving = $state(false), status = $state(''), error = $state(''), attempt = $state(0);
 let theme = $state<ThemeChoice>(loadTheme());
 $effect(() => {
  attempt; let cancelled = false;
  loading = true; loadError = '';
  void client.getProfile(client.userId).then(p => { if (!cancelled) name = p.displayname ?? ''; }).catch(e => { if (!cancelled) loadError = describeError(e); }).finally(() => { if (!cancelled) loading = false; });
  return () => { cancelled = true; };
 });
 async function save() {
  if (saving) return; saving = true; status = ''; error = '';
  try { await client.setDisplayName(name); onProfileChanged(name.trim()); status = 'Display name saved.'; } catch (e) { error = describeError(e); } finally { saving = false; }
 }
</script>
<div class="rest-stack" data-testid="settings">
 <section class="rest-section"><h2>Profile</h2>
  {#if loading}<p role="status">Loading your profile…</p>{:else if loadError}<p class="rest-error" role="alert">Couldn't load your profile. {loadError}</p><Button variant="outline" onclick={() => attempt++}>Try again</Button>{:else}<form class="rest-stack" onsubmit={e => { e.preventDefault(); void save(); }}><label for="settings-displayname">Display name</label><Input id="settings-displayname" bind:value={name} aria-describedby="displayname-help" /><p id="displayname-help" class="rest-muted">Shown to people in your rooms instead of your Matrix ID.</p><Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button><p role="status" data-testid="displayname-status" class:rest-error={!!error}>{error || status}</p></form>{/if}
 </section>
 <section class="rest-section"><h2>Appearance</h2><fieldset class="rest-choices"><legend>Theme</legend>{#each ['system', 'light', 'dark'] as choice}<label><input type="radio" name="theme" value={choice} checked={theme === choice} onchange={() => { theme = choice as ThemeChoice; saveTheme(theme); }} />{choice === 'system' ? 'Match system' : choice === 'light' ? 'Day' : 'Night'}</label>{/each}</fieldset></section>
 <section class="rest-section"><h2>This session</h2><dl class="rest-facts"><dt>Matrix ID</dt><dd>{client.userId}</dd><dt>Device</dt><dd>{client.session.deviceId}</dd><dt>Homeserver</dt><dd>{client.session.homeserverUrl}</dd></dl><p class="rest-muted">Notification settings and end-to-end encryption are not available in this version yet.</p><Button variant="destructive" onclick={signOut}>Sign out</Button></section>
 <AccountSettings {client} {onDeactivated} />
</div>
