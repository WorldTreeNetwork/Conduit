<script lang="ts">
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import { describeError, type MatrixClient, type PublicRoom } from '#lib/session.js';
 let { client, version, onJoined }: { client: MatrixClient; version: number; onJoined: (id: string) => void } = $props();
 let term = $state(''), rooms = $state<PublicRoom[]>([]), next = $state<string | undefined>(), error = $state('');
 let loading = $state(true), moreBusy = $state(false), joining = $state<string | null>(null), joinError = $state('');
 let generation = 0;
 $effect(() => {
  const query = term.trim(), request = ++generation;
  loading = true; error = ''; rooms = []; next = undefined;
  const timer = setTimeout(() => {
   void client.publicRooms({ term: query || undefined }).then(page => {
    if (generation !== request) return;
    rooms = page.chunk ?? []; next = page.next_batch; loading = false;
   }).catch(e => { if (generation === request) { error = describeError(e); loading = false; } });
  }, 300);
  return () => { clearTimeout(timer); generation++; };
 });
 async function more() {
  if (!next || moreBusy) return;
  const request = generation;
  moreBusy = true; error = '';
  try { const page = await client.publicRooms({ term: term.trim() || undefined, since: next }); if (request === generation) { rooms = [...rooms, ...(page.chunk ?? [])]; next = page.next_batch; } }
  catch (e) { if (request === generation) error = describeError(e); }
  finally { moreBusy = false; }
 }
 async function join(id: string) {
  joining = id; joinError = '';
  try { onJoined(await client.joinRoom(id)); } catch (e) { joinError = describeError(e); } finally { joining = null; }
 }
 const joinedIds = $derived.by(() => { version; return new Set(client.roomList().filter(r => r.membership === 'join').map(r => r.roomId)); });
</script>
<div class="rest-stack" data-testid="room-directory">
 <label for="directory-search">Search public rooms</label><Input id="directory-search" type="search" bind:value={term} placeholder="Search public rooms" />
 <div aria-live="polite" aria-busy={loading}>
  {#if loading}<p role="status">Looking for rooms…</p>{:else if !rooms.length && !error}<p>{term.trim() ? `No public rooms match “${term.trim()}”.` : 'No public rooms yet.'}</p>{/if}
  {#if error}<p class="rest-error" role="alert">Couldn't load the directory. {error}</p>{/if}
  <ul class="rest-list">{#each rooms as room (room.room_id)}{@const name = room.name || room.canonical_alias || room.room_id}<li data-testid="directory-room" data-room-id={room.room_id}><div><strong>{name}</strong><small>{room.num_joined_members} {room.num_joined_members === 1 ? 'member' : 'members'}{room.topic ? ` · ${room.topic}` : ''}</small></div>{#if joinedIds.has(room.room_id)}<Button variant="outline" onclick={() => onJoined(room.room_id)}>Open</Button>{:else}<Button disabled={joining !== null} aria-label={`Join ${name}`} onclick={() => void join(room.room_id)}>{joining === room.room_id ? 'Joining…' : 'Join'}</Button>{/if}</li>{/each}</ul>
  {#if joinError}<p class="rest-error" role="alert">{joinError}</p>{/if}
  {#if next}<Button variant="outline" disabled={moreBusy} onclick={() => void more()}>{moreBusy ? 'Loading…' : 'Show more rooms'}</Button>{/if}
 </div>
</div>
