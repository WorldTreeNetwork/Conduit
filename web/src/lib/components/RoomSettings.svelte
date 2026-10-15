<script lang="ts">
 import { untrack } from 'svelte';
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import { describeError, type MatrixClient, type Room, type JsonObject } from '#lib/session.js';
 let { client, room, version }: { client: MatrixClient; room: Room; version: number } = $props();
 // The dialog is keyed by room; sync must not replace an in-progress draft.
 const initialRoom = untrack(() => room);
 let name = $state(initialRoom.explicitName ?? ''), topic = $state(initialRoom.topic ?? ''), joinRule = $state(initialRoom.joinRule ?? 'invite'), visibility = $state(String(initialRoom.getStateContent('m.room.history_visibility')?.history_visibility ?? 'shared'));
 let status = $state(''), error = $state(''), pending = $state(false);
 const me = $derived.by(() => { version; return room.powerLevel(client.userId); });
 function can(type: string) { version; const pl = room.getStateContent('m.room.power_levels') ?? {}; const events = (pl.events ?? {}) as JsonObject; return me >= (typeof events[type] === 'number' ? events[type] as number : typeof pl.state_default === 'number' ? pl.state_default : 50); }
 const readOnly = $derived.by(() => { version; return !can('m.room.name') && !can('m.room.topic') && !can('m.room.join_rules'); });
 const members = $derived.by(() => { version; return room.members().filter(m => m.membership === 'join').sort((a,b) => room.powerLevel(b.userId) - room.powerLevel(a.userId) || a.userId.localeCompare(b.userId)); });
 async function save() {
  if (pending) return; pending = true; error = ''; status = '';
  try {
   const changes: [string, JsonObject][] = [];
   if (name.trim() !== (room.explicitName ?? '') && can('m.room.name')) changes.push(['m.room.name', { name: name.trim() }]);
   if (topic.trim() !== (room.topic ?? '') && can('m.room.topic')) changes.push(['m.room.topic', { topic: topic.trim() }]);
   if (joinRule !== (room.joinRule ?? 'invite') && can('m.room.join_rules')) changes.push(['m.room.join_rules', { join_rule: joinRule }]);
   if (visibility !== String(room.getStateContent('m.room.history_visibility')?.history_visibility ?? 'shared') && can('m.room.history_visibility')) changes.push(['m.room.history_visibility', { history_visibility: visibility }]);
   for (const [type, content] of changes) await client.setRoomState(room.roomId, type, content);
   status = changes.length ? 'Saved.' : 'Nothing to change.';
  } catch (e) { error = describeError(e); } finally { pending = false; }
 }
 async function picture(input: HTMLInputElement) {
  const file = input.files?.[0]; if (!file || pending) return;
  pending = true; error = ''; status = '';
  try { const url = await client.uploadFile(file, file.name); await client.setRoomState(room.roomId, 'm.room.avatar', { url, info: { mimetype: file.type, size: file.size } }); status = 'Room picture updated.'; } catch (e) { error = describeError(e); } finally { pending = false; input.value = ''; }
 }
 async function role(id: string, level: number) {
  pending = true; error = ''; status = '';
  try { await client.setPowerLevel(room.roomId, id, level); status = 'Role updated.'; } catch (e) { error = describeError(e); } finally { pending = false; }
 }
</script>
<div class="rest-stack">
 {#if readOnly}<p class="rest-muted">Only moderators and admins can change these settings.</p>{/if}
 <form class="rest-stack" onsubmit={e => { e.preventDefault(); void save(); }}>
  <label for="rs-name">Name</label><Input id="rs-name" bind:value={name} disabled={pending || !can('m.room.name')} />
  <label for="rs-topic">Topic</label><textarea id="rs-topic" bind:value={topic} disabled={pending || !can('m.room.topic')}></textarea>
  <label for="rs-join">Who can join</label><select id="rs-join" bind:value={joinRule} disabled={pending || !can('m.room.join_rules')}><option value="invite">Only people who are invited</option><option value="public">Anyone who knows the address</option><option value="knock">Anyone can ask to join</option></select>
  <label for="rs-history">Who can read history</label><select id="rs-history" bind:value={visibility} disabled={pending || !can('m.room.history_visibility')}><option value="shared">Members, including history from before they joined</option><option value="invited">Members, from the time they were invited</option><option value="joined">Members, from the time they joined</option><option value="world_readable">Anyone, even without joining</option></select>
  <Button type="submit" disabled={pending || readOnly}>{pending ? 'Saving…' : 'Save changes'}</Button>
  <label for="rs-picture">Change picture</label><Input id="rs-picture" type="file" accept="image/*" disabled={pending || !can('m.room.avatar')} onchange={e => void picture(e.currentTarget)} />
 </form>
 <p role="status" class:rest-error={!!error}>{error || status}</p>
 <section class="rest-section"><h3>Roles</h3><ul class="rest-list">{#each members as member (member.userId)}{@const level = room.powerLevel(member.userId)}<li><strong>{room.memberName(member.userId)}</strong><select aria-label={`Role for ${room.memberName(member.userId)}`} value={[0,50,100].includes(level) ? level : ''} disabled={pending || !can('m.room.power_levels') || member.userId === client.userId || level >= me} onchange={e => void role(member.userId, Number(e.currentTarget.value))}>{#if ![0,50,100].includes(level)}<option value="">Custom ({level})</option>{/if}{#each [{ level: 0, label: 'Member' }, { level: 50, label: 'Moderator' }, { level: 100, label: 'Admin' }] as item}{#if item.level <= me || item.level === level}<option value={item.level}>{item.label}</option>{/if}{/each}</select></li>{/each}</ul></section>
</div>
