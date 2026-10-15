<script lang="ts">
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import * as Dialog from '#lib/components/ui/dialog/index.js';
 import { describeError, MatrixError, type MatrixClient, type DeviceInfo } from '#lib/session.js';
 let { client, onDeactivated }: { client: MatrixClient; onDeactivated: () => void } = $props();
 let devices = $state<DeviceInfo[] | null>(null), deviceError = $state(''), deviceStatus = $state(''), renaming = $state(''), newName = $state(''), renameBusy = $state(false), attempt = $state(0);
 let current = $state(''), next = $state(''), repeat = $state(''), logoutOthers = $state(true), passwordBusy = $state(false), passwordStatus = $state(''), passwordError = $state('');
 let confirmOpen = $state(false), action = $state<'devices' | 'deactivate'>('devices'), ids = $state<string[]>([]), password = $state(''), confirmError = $state(''), pending = $state(false), erase = $state(false);
 let confirmTrigger: HTMLElement | null = null;
 let deviceGeneration = 0;
 function authError(e: unknown) { return e instanceof MatrixError && (e.errcode === 'M_FORBIDDEN' || e.httpStatus === 401) ? 'That password is not right.' : describeError(e); }
 async function load() {
  const request = ++deviceGeneration;
  deviceError = '';
  try { const list = await client.listDevices(); if (request === deviceGeneration) devices = list.sort((a,b) => Number(b.device_id === client.session.deviceId) - Number(a.device_id === client.session.deviceId) || (b.last_seen_ts ?? 0) - (a.last_seen_ts ?? 0)); }
  catch (e) { if (request === deviceGeneration) deviceError = describeError(e); }
 }
 $effect(() => { attempt; void load(); return () => { deviceGeneration++; }; });
 const others = $derived((devices ?? []).filter(d => d.device_id !== client.session.deviceId));
 async function rename(id: string) {
  if (renameBusy) return; renameBusy = true; deviceStatus = '';
  try { await client.renameDevice(id, newName); renaming = ''; deviceStatus = 'Device renamed.'; await load(); } catch (e) { deviceStatus = describeError(e); } finally { renameBusy = false; }
 }
 function confirm(kind: typeof action, deviceIds: string[] = []) { confirmTrigger = document.activeElement as HTMLElement | null; action = kind; ids = deviceIds; password = ''; confirmError = ''; confirmOpen = true; }
 async function confirmed() {
  if (!password || pending) return; pending = true; confirmError = '';
  try {
   if (action === 'deactivate') { await client.deactivate(password, erase); onDeactivated(); }
   else { await client.deleteDevices(ids, password); deviceStatus = ids.length > 1 ? 'Other devices signed out.' : 'Device signed out.'; await load(); }
   confirmOpen = false;
  } catch (e) { confirmError = authError(e); } finally { pending = false; password = ''; }
 }
 async function changePassword() {
  passwordError = ''; passwordStatus = '';
  if (!current) { passwordError = 'Enter your current password.'; return; }
  if (next.length < 8) { passwordError = 'Use at least 8 characters.'; return; }
  if (next !== repeat) { passwordError = "The passwords don't match."; return; }
  if (passwordBusy) return; passwordBusy = true;
  try { await client.changePassword(current, next, logoutOthers); current = ''; next = ''; repeat = ''; passwordStatus = logoutOthers ? 'Password changed. Your other devices were signed out.' : 'Password changed.'; await load(); } catch (e) { passwordError = authError(e); } finally { passwordBusy = false; }
 }
 function lastSeen(device: DeviceInfo) {
  return [device.last_seen_ts ? `Last active ${new Date(device.last_seen_ts).toLocaleString()}` : '', device.last_seen_ip].filter(Boolean).join(' · ') || 'No activity recorded';
 }
</script>
<section class="rest-section"><h2>Where you're signed in</h2>
 {#if deviceError}<p class="rest-error" role="alert">Couldn't load your devices. {deviceError}</p><Button variant="outline" onclick={() => attempt++}>Try again</Button>{:else if !devices}<p role="status">Loading devices…</p>{/if}
 {#if devices}<ul class="rest-list">{#each devices as device (device.device_id)}<li data-testid="device-row" data-device-id={device.device_id}><div>{#if renaming === device.device_id}<form class="rest-stack" onsubmit={e => { e.preventDefault(); void rename(device.device_id); }}><label for="rename-device">New device name</label><Input id="rename-device" bind:value={newName} onkeydown={e => { if (e.key === 'Escape') renaming = ''; }} /><div class="rest-row"><Button type="submit" disabled={renameBusy}>Save device name</Button><Button variant="outline" disabled={renameBusy} onclick={() => { renaming = ''; }}>Cancel</Button></div></form>{:else}<strong>{device.display_name || device.device_id}</strong>{#if device.device_id === client.session.deviceId}<span class="rest-badge">This device</span>{/if}{/if}<small>{device.device_id} · {lastSeen(device)}</small></div><div class="rest-row">{#if renaming !== device.device_id}<Button variant="outline" aria-label={`Rename ${device.display_name || device.device_id}`} onclick={() => { renaming = device.device_id; newName = device.display_name ?? ''; }}>Rename</Button>{/if}{#if device.device_id !== client.session.deviceId}<Button variant="outline" aria-label={`Sign out ${device.display_name || device.device_id}`} onclick={() => confirm('devices', [device.device_id])}>Sign out</Button>{/if}</div></li>{/each}</ul>{/if}
 {#if others.length > 1}<Button variant="destructive" onclick={() => confirm('devices', others.map(d => d.device_id))}>Sign out all other devices</Button>{/if}<p role="status">{deviceStatus}</p>
</section>
<section class="rest-section"><h2>Password</h2><form class="rest-stack" onsubmit={e => { e.preventDefault(); void changePassword(); }}>
 <label for="pw-current">Current password</label><Input id="pw-current" type="password" autocomplete="current-password" bind:value={current} />
 <label for="pw-new">New password</label><Input id="pw-new" type="password" autocomplete="new-password" bind:value={next} />
 <label for="pw-repeat">Confirm new password</label><Input id="pw-repeat" type="password" autocomplete="new-password" bind:value={repeat} />
 <label class="rest-check"><input type="checkbox" bind:checked={logoutOthers} />Sign out my other devices</label><Button type="submit" disabled={passwordBusy}>{passwordBusy ? 'Changing…' : 'Change password'}</Button><p role="status" class:rest-error={!!passwordError}>{passwordError || passwordStatus}</p>
</form></section>
<section class="rest-section"><h2>Deactivate account</h2><p class="rest-muted">This permanently closes your account: you leave every room, all your devices are signed out, and the username can't be used again.</p><label class="rest-check"><input type="checkbox" bind:checked={erase} />Also erase my profile and hide my messages from people who join later</label><Button variant="destructive" onclick={() => confirm('deactivate')}>Deactivate account</Button></section>
<Dialog.Root bind:open={confirmOpen}><Dialog.Content onCloseAutoFocus={e => { e.preventDefault(); confirmTrigger?.focus(); }} showCloseButton={!pending} onInteractOutside={e => { if (pending) e.preventDefault(); }} onEscapeKeydown={e => { if (pending) e.preventDefault(); }}><Dialog.Header><Dialog.Title>{action === 'deactivate' ? 'Deactivate your account?' : ids.length > 1 ? `Sign out ${ids.length} devices?` : 'Sign out this device?'}</Dialog.Title><Dialog.Description>{action === 'deactivate' ? 'This cannot be undone. Confirm with your password.' : 'It will need to sign in again. Confirm with your password.'}</Dialog.Description></Dialog.Header><form class="rest-stack" onsubmit={e => { e.preventDefault(); void confirmed(); }}><label for="confirm-password">Your password</label><Input id="confirm-password" type="password" autocomplete="current-password" bind:value={password} required disabled={pending} />{#if confirmError}<p class="rest-error" role="alert">{confirmError}</p>{/if}<Dialog.Footer><Button variant="outline" disabled={pending} onclick={() => { confirmOpen = false; password = ''; }}>Cancel</Button><Button variant="destructive" type="submit" disabled={pending || !password}>{pending ? 'Please wait…' : action === 'deactivate' ? 'Deactivate' : 'Sign out'}</Button></Dialog.Footer></form></Dialog.Content></Dialog.Root>
