<script lang="ts">
 import { onMount, tick, untrack } from 'svelte';
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import * as Dialog from '#lib/components/ui/dialog/index.js';
 import { ScrollArea } from '#lib/components/ui/scroll-area/index.js';
 import * as Avatar from '#lib/components/ui/avatar/index.js';
 import { describeError, relatesTo, type MatrixClient } from '#lib/session.js';
 import Settings from './Settings.svelte';
 import RoomSettings from './RoomSettings.svelte';
 import MemberPanel from './MemberPanel.svelte';
 import Directory from './Directory.svelte';
 import ThreadPanel from './ThreadPanel.svelte';
 import ConnectionBanner from './ConnectionBanner.svelte';
 import Message from './Message.svelte';
 import Media from './Media.svelte';
 import UserSuggestions from './UserSuggestions.svelte';
 import Reauth from './Reauth.svelte';
 import '#lib/styles/rest.css';
 let { client, displayName, signOut, onProfileChanged, onDeactivated }: { client: MatrixClient; displayName: string; signOut: () => void; onProfileChanged: (name: string) => void; onDeactivated: () => void } = $props();
 let settings = $state(false);
 let panel = $state<'members' | 'directory' | 'room-settings' | 'thread'>('members');
 let panelOpen = $state(false), rootId = $state('');
 let panelTrigger: HTMLElement | null = null;
 let attachment = $state<HTMLInputElement | null>(null);
 let attachmentError = $state('');
 const softLoggedOut = $derived.by(() => { version; return client.softLoggedOut; });
 function showPanel(kind: typeof panel, root = '') { panelTrigger = document.activeElement as HTMLElement | null; panel = kind; rootId = root; panelOpen = true; }
 async function attach(input: HTMLInputElement) {
  const file = input.files?.[0], id = selected;
  if (!file || !id) return;
  attachmentError = '';
  try {
   let size = {};
   if (file.type.startsWith('image/') && typeof createImageBitmap === 'function') {
    const bitmap = await createImageBitmap(file).catch(() => null);
    if (bitmap) { size = { w: bitmap.width, h: bitmap.height }; bitmap.close(); }
   }
   client.sendAttachment(id, file, size);
  } catch (e) { attachmentError = describeError(e); }
  finally { input.value = ''; }
 }

 let version = $state(0);
 let selected = $state<string | null>(null);
 let dialog = $state<'create' | 'join' | 'invite'>('create');
 let open = $state(false);
 let dialogTrigger: HTMLElement | null = null;
 let field = $state('');
 let working = $state(false);
 let error = $state('');
 let historyError = $state('');
 let paging = $state(false);
 let drafts = $state<Record<string, string>>({});
 let viewport = $state<HTMLElement | null>(null);
 let nearBottom = true;
 let previousRoom: string | null = null;
 let previousLast: string | undefined;
 const entries = $derived.by(() => { version; return client.roomList(); });
 const joined = $derived(entries.filter(e => e.membership === 'join'));
 const invitations = $derived(entries.filter(e => e.membership === 'invite'));
 const view = $derived.by(() => {
  version;
  const room = selected ? client.getRoom(selected) : undefined;
  if (!room || room.membership !== 'join') return null;
  const relations = room.aggregations(client.userId);
  return {
   room, name: room.displayName(client.userId), topic: room.topic, exhausted: room.historyExhausted,
   messages: room.timeline.filter(e => e.type === 'm.room.message' && !relations.hidden.has(e.event_id)),
   typing: room.typing.filter(id => id !== client.userId).map(id => room.memberName(id)),
   pending: client.sendQueue.forRoom(room.roomId).filter(e => e.type === 'm.room.message' && relatesTo(e).relType !== 'm.thread' && (!e.eventId || !room.hasEvent(e.eventId)))
  };
 });
 function readHash() {
  if (selected) client.setTyping(selected, false);
  settings = location.hash === '#/settings'; panelOpen = false; attachmentError = '';
  const match = /^#\/room\/(.+)$/.exec(location.hash);
  try { selected = match ? decodeURIComponent(match[1]) : null; }
  catch { selected = null; location.replace('#/'); }
  historyError = '';
 }
 function home() { location.hash = '#/'; selected = null; settings = false; }
 function roomRoute(id: string) { settings = false; panelOpen = false; location.hash = `#/room/${encodeURIComponent(id)}`; selected = id; }
 function show(kind: typeof dialog) { dialogTrigger = document.activeElement as HTMLElement | null; dialog = kind; field = ''; error = ''; open = true; }
 async function submit() {
  if (working || !field.trim()) return;
  const kind = dialog, target = selected;
  working = true; error = '';
  try {
   if (kind === 'create') roomRoute(await client.createRoom({ name: field, visibility: 'private' }));
   else if (kind === 'join') roomRoute(await client.joinRoom(field));
   else if (target) await client.invite(target, field);
   open = false;
  } catch (e) { error = describeError(e); }
  finally { working = false; }
 }
 async function accept(id: string) {
  working = true; error = '';
  try { roomRoute(await client.acceptInvite(id)); }
  catch (e) { error = describeError(e); }
  finally { working = false; }
 }
 async function history() {
  if (!selected || paging) return;
  const target = selected, height = viewport?.scrollHeight ?? 0, top = viewport?.scrollTop ?? 0;
  paging = true; historyError = '';
  try {
   await client.paginateBack(target); await tick();
   if (selected === target && viewport) viewport.scrollTop = top + viewport.scrollHeight - height;
  } catch (e) { if (selected === target) historyError = describeError(e); }
  finally { paging = false; }
 }
 function send() {
  if (!selected || !drafts[selected]?.trim()) return;
  nearBottom = true;
  client.sendMessage(selected, drafts[selected].trim()); client.setTyping(selected, false); drafts[selected] = '';
 }
 onMount(() => {
  readHash();
  const unsubscribe = client.subscribe(() => { version = client.getVersion(); });
  window.addEventListener('hashchange', readHash); client.start();
  return () => { unsubscribe(); window.removeEventListener('hashchange', readHash); void client.stop(); };
 });
 $effect(() => {
  version;
  if (selected && client.syncHealth.ready && !view) home();
 });
 $effect(() => {
  version;
  if (selected && view && document.visibilityState === 'visible') untrack(() => { void client.markRead(selected!); });
 });
 $effect(() => {
  const id = selected, last = view?.pending.at(-1)?.txnId ?? view?.messages.at(-1)?.event_id;
  if (id !== previousRoom || (last !== previousLast && nearBottom)) {
   void tick().then(() => { if (selected === id && viewport) viewport.scrollTop = viewport.scrollHeight; });
  }
  previousRoom = id; previousLast = last;
 });
</script>

<svelte:window onfocus={() => { if (selected) void client.markRead(selected); }} />
{#if softLoggedOut}<Reauth {client} {signOut} />{:else}
<div class="workspace"><ConnectionBanner {client} {version} />
<main class="chat" class:in-room={!!selected || settings}>
 <aside class="rail" aria-label="Rooms">
  <header class="identity"><a class="brand" href="#/">Conduit</a><p data-testid="profile-display-name">{displayName}</p><p class="account">{client.userId}</p></header>
  <div class="actions"><Button onclick={() => show('create')}>Create room</Button><Button variant="outline" onclick={() => show('join')}>Join room</Button></div>
  <ScrollArea class="min-h-0 flex-1">
   {#if invitations.length}<section class="invitations" aria-label="Invitations"><h2>Invitations</h2>{#each invitations as entry (entry.roomId)}<div class="invitation"><strong>{entry.name}</strong><p>{entry.inviter ?? 'You have been invited'}</p><Button variant="outline" disabled={working} onclick={() => void accept(entry.roomId)}>Accept invitation</Button></div>{/each}</section>{/if}
   <nav aria-label="Joined rooms"><h2 class="rail-label">Your rooms <span>{joined.length}</span></h2>
    {#each joined as entry (entry.roomId)}
     <a class="room-link" class:active={selected === entry.roomId} href={`#/room/${encodeURIComponent(entry.roomId)}`} aria-current={selected === entry.roomId ? 'page' : undefined}>
      <span class="room-name">{entry.name}</span>{#if entry.unread > 0}<span class="count" aria-label={`${entry.unread} unread`}>{entry.unread}</span>{/if}<span class="preview">{entry.preview?.body || 'No messages yet'}</span>
     </a>
    {:else}<p class="rail-empty">Your conversations will appear here.</p>{/each}
   </nav>
  </ScrollArea>
  {#if error && !open}<p class="error action-error" role="alert">{error}</p>{/if}
  <footer><ConnectionBanner {client} {version} line /><div class="rest-row"><Button variant="outline" href="#/settings">Settings</Button><Button variant="outline" onclick={() => showPanel('directory')}>Directory</Button><Button variant="outline" onclick={signOut}>Sign out</Button></div></footer>
 </aside>
 <section class="conversation" aria-label={settings ? 'Settings' : view?.name ?? 'Home'}>
  {#if settings}<ScrollArea class="min-h-0 flex-1"><div class="settings-page"><a href="#/" class="rest-back">← All rooms</a><h1>Settings</h1><Settings {client} {signOut} {onProfileChanged} {onDeactivated} /></div></ScrollArea>
  {:else if view}
   <header class="room-heading"><a class="back" href="#/">← Rooms</a><div><h1>{view.name}</h1>{#if view.topic}<p>{view.topic}</p>{/if}</div><div class="room-tools"><Button variant="outline" onclick={() => show('invite')}>Invite</Button><Button variant="outline" onclick={() => showPanel('members')}>People</Button><Button variant="outline" onclick={() => showPanel('room-settings')}>Room settings</Button></div></header>
   <ScrollArea class="min-h-0 flex-1" bind:viewportRef={viewport} onscrollcapture={() => { if (viewport) nearBottom = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 100; }}>
    <div class="timeline" role="log" aria-label="Messages" aria-live="polite" aria-relevant="additions">
     <div class="history">{#if !view.exhausted}<Button variant="ghost" disabled={paging} onclick={() => void history()}>{paging ? 'Loading history…' : 'Load older messages'}</Button>{:else}<p>Beginning of conversation</p>{/if}{#if historyError}<p class="error" role="alert">{historyError}</p>{/if}</div>
     {#each view.messages as event (event.event_id)}
      <Message {client} room={view.room} {event} {version} openThread={id => showPanel('thread', id)} />
     {/each}
     {#each view.pending as message (message.txnId)}
      <article class="message pending" data-txn-id={message.txnId}><Avatar.Root class="size-9"><Avatar.Fallback class="nameplate">{displayName.replace('@', '').slice(0, 2).toUpperCase()}</Avatar.Fallback></Avatar.Root><div class="message-content"><div class="byline"><strong>{displayName}</strong><span>{message.status === 'failed' ? 'Not sent' : message.status === 'sent' ? 'Sent · awaiting sync' : 'Sending…'}</span></div>{#if ['m.image', 'm.file', 'm.audio', 'm.video'].includes(String(message.content.msgtype))}<Media {client} content={message.content} localUrl={message.attachment?.localUrl} />{:else}<p>{String(message.content.body ?? '')}</p>{/if}{#if message.status === 'failed'}<p class="error">{message.error}</p><Button variant="outline" onclick={() => client.retrySend(message.txnId)}>Retry</Button>{/if}</div></article>
     {/each}
     {#if !view.messages.length && !view.pending.length}<p class="empty-thread">A new conversation. Send the first message.</p>{/if}
    </div>
   </ScrollArea>
   <p class="typing" data-testid="typing-indicator" aria-live="polite">{view.typing.length === 1 ? `${view.typing[0]} is typing…` : view.typing.length === 2 ? `${view.typing[0]} and ${view.typing[1]} are typing…` : view.typing.length > 2 ? 'Several people are typing…' : ''}</p>
   <form class="composer" onsubmit={e => { e.preventDefault(); send(); }}><label for="message">Message {view.name}</label><div><Input id="message" name="message" autocomplete="off" bind:value={drafts[selected!]} placeholder="Write a message…" class="h-11 min-w-0" oninput={e => { if (selected) client.setTyping(selected, !!e.currentTarget.value.trim()); }} onblur={() => { if (selected) client.setTyping(selected, false); }} /><Button variant="outline" class="h-11" aria-label="Attach a file" onclick={() => attachment?.click()}>Attach</Button><Button type="submit" class="h-11" disabled={!selected || !drafts[selected]?.trim()}>Send</Button></div><input bind:this={attachment} type="file" class="sr-only" tabindex="-1" aria-label="Attachment" onchange={e => void attach(e.currentTarget)} />{#if attachmentError}<p class="error" role="alert">{attachmentError}</p>{/if}</form>
  {:else}<div class="home"><span class="eyebrow">Your conversations</span><h1>A place to catch up.</h1><p>Choose a room, or start a conversation with someone.</p><div><Button onclick={() => show('create')}>Create room</Button><Button variant="outline" onclick={() => show('join')}>Join room</Button></div></div>{/if}
  {#if error && !open}<p class="error action-error" role="alert">{error}</p>{/if}
 </section>
</main>
</div>
{/if}
<Dialog.Root bind:open>
 <Dialog.Content onCloseAutoFocus={e => { e.preventDefault(); dialogTrigger?.focus(); }} showCloseButton={!working} onInteractOutside={e => { if (working) e.preventDefault(); }} onEscapeKeydown={e => { if (working) e.preventDefault(); }}>
  <Dialog.Header><Dialog.Title>{dialog === 'create' ? 'Create room' : dialog === 'join' ? 'Join room' : 'Invite someone'}</Dialog.Title><Dialog.Description>{dialog === 'create' ? 'Start a private conversation. You can invite people next.' : dialog === 'join' ? 'Enter a room ID or alias, including its homeserver.' : `Invite a Matrix account to ${view?.name ?? 'this room'}.`}</Dialog.Description></Dialog.Header>
  <form class="dialog-form" onsubmit={e => { e.preventDefault(); void submit(); }}><label for="room-field">{dialog === 'create' ? 'Room name' : dialog === 'join' ? 'Room ID or alias' : 'Matrix user ID'}</label><Input id="room-field" bind:value={field} disabled={working} required placeholder={dialog === 'create' ? 'Weekend plans' : dialog === 'join' ? '#room:example.org' : '@person:example.org'} />{#if dialog === 'invite'}<UserSuggestions {client} term={field} onPick={id => { field = id; }} />{/if}{#if error}<p class="error" role="alert">{error}</p>{/if}<Dialog.Footer><Button type="button" variant="outline" disabled={working} onclick={() => { open = false; }}>Cancel</Button><Button type="submit" disabled={working || !field.trim()}>{working ? 'Please wait…' : dialog === 'create' ? 'Create room' : dialog === 'join' ? 'Join room' : 'Send invitation'}</Button></Dialog.Footer></form>
 </Dialog.Content>
</Dialog.Root>

<Dialog.Root bind:open={panelOpen}>
 <Dialog.Content class="rest-dialog" onOpenAutoFocus={e => { if (panel === 'thread') { e.preventDefault(); requestAnimationFrame(() => document.getElementById('thread-message')?.focus()); } }} onCloseAutoFocus={e => { e.preventDefault(); panelTrigger?.focus(); }}>
  <Dialog.Header><Dialog.Title>{panel === 'members' ? 'People' : panel === 'directory' ? 'Room directory' : panel === 'thread' ? 'Thread' : 'Room settings'}</Dialog.Title><Dialog.Description>{panel === 'directory' ? 'Public rooms on this server' : view?.name ?? 'Your conversation'}</Dialog.Description></Dialog.Header>
  {#if panel === 'directory'}<Directory {client} {version} onJoined={roomRoute} />{:else if view}
   {#key `${view.room.roomId}:${panel}:${rootId}`}
    {#if panel === 'members'}<MemberPanel {client} room={view.room} {version} />{:else if panel === 'thread'}<ThreadPanel {client} room={view.room} {rootId} {version} />{:else}<RoomSettings {client} room={view.room} {version} />{/if}
   {/key}
  {/if}
 </Dialog.Content>
</Dialog.Root>

<style>
 .settings-page { max-width:48rem; margin:auto; padding:1.5rem; } .settings-page h1 { font-size:var(--text-2xl); margin:1rem 0; }
 .typing { min-height:1.5rem; padding:0 1rem; color:var(--color-ink-muted); font-size:var(--text-sm); }
 .workspace { height:100dvh; display:flex; flex-direction:column; }
 .chat { display:flex; flex:1; min-height:0; overflow:hidden; }
 .rail { display:flex; flex-direction:column; width:var(--board-width); flex-shrink:0; background:var(--color-board); color:var(--color-board-ink); }
 .identity { padding:1.5rem 1.25rem 1rem; border-bottom:1px solid var(--color-board-rule); }
 .brand { font-family:var(--font-title); font-weight:600; font-size:var(--text-2xl); font-variation-settings:'wdth' 100; }
 .identity p { margin-top:.5rem; overflow-wrap:anywhere; }
 .identity .account { color:var(--color-board-ink-muted); font-size:var(--text-xs); margin-top:0; }
 .actions { display:flex; flex-wrap:wrap; gap:.5rem; padding:1rem 1.25rem; }
 .rail-label { display:flex; justify-content:space-between; padding:1rem 1.25rem .5rem; color:var(--color-board-ink-muted); font-size:var(--text-sm); }
 .rail-label span { font-family:var(--font-text); }
 .room-link { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:.25rem .5rem; padding:.75rem 1.25rem; border-left:3px solid transparent; }
 .room-link:hover { background:var(--color-board-raised); }
 .room-link.active { background:var(--color-board-selected); border-left-color:var(--color-brass); }
 .room-name { font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
 .preview { grid-column:1/-1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--text-sm); color:var(--color-board-ink-muted); }
 .count { border-radius:var(--radius-pill); padding:0 .5rem; background:var(--color-brass); color:var(--color-brass-ink); font-size:var(--text-sm); }
 .rail-empty { padding:1rem 1.25rem; color:var(--color-board-ink-muted); }
 .rail footer { padding:1rem 1.25rem; border-top:1px solid var(--color-board-rule); }
 .conversation { min-width:0; flex:1; display:flex; flex-direction:column; background:var(--color-surface); }
 .room-heading { min-height:6rem; padding:1.25rem 2rem; display:flex; gap:1rem; align-items:center; border-bottom:1px solid var(--color-rule); }
 .room-heading > div { min-width:0; flex:1; }
 .room-heading .room-tools { display:flex; flex-wrap:wrap; gap:.5rem; flex:0 1 auto; }
 .room-heading h1 { font-size:var(--text-xl); overflow-wrap:anywhere; }
 .room-heading p { color:var(--color-ink-muted); font-size:var(--text-sm); overflow-wrap:anywhere; }
 .back { display:none; }
 .timeline { max-width:54rem; margin:auto; padding:1rem 2rem 2rem; }
 .history { text-align:center; color:var(--color-ink-muted); font-size:var(--text-sm); padding-bottom:1.5rem; }
 .message { display:flex; gap:.75rem; padding:.75rem 0; }
 .message-content { min-width:0; flex:1; }
 .byline { display:flex; gap:.75rem; align-items:baseline; flex-wrap:wrap; }
 .byline strong { font-size:var(--text-sm); overflow-wrap:anywhere; }
 .byline span { font-size:var(--text-xs); color:var(--color-ink-muted); }
 .message-content > p { white-space:pre-wrap; overflow-wrap:anywhere; }
 :global(.nameplate) { background:var(--color-tint-1); color:var(--color-tint-1-ink); font-size:var(--text-xs); }
 .composer { border-top:1px solid var(--color-rule); padding:1rem 2rem 1.5rem; }
 .composer label { display:block; font-size:var(--text-sm); color:var(--color-ink-muted); margin-bottom:.5rem; }
 .composer > div { display:flex; gap:.75rem; }
 .home { margin:auto; padding:2rem; max-width:38rem; }
 .eyebrow { color:var(--color-brass-text); font-size:var(--text-sm); }
 .home h1 { font-size:var(--text-2xl); margin:.75rem 0; }
 .home p,.empty-thread { color:var(--color-ink-muted); }
 .home > div { display:flex; flex-wrap:wrap; gap:.75rem; margin-top:1.5rem; }
 .error { color:var(--color-signal-ink); font-size:var(--text-sm); }
 .action-error { padding:1rem; }
 .dialog-form { display:flex; flex-direction:column; gap:.75rem; }
 .dialog-form label { font-weight:600; font-size:var(--text-sm); }
 .invitations { padding:1rem 1.25rem; border-bottom:1px solid var(--color-board-rule); }
 .invitations h2 { font-size:var(--text-sm); color:var(--color-board-ink-muted); }
 .invitation { margin-top:.75rem; overflow-wrap:anywhere; }
 .invitation p { font-size:var(--text-xs); margin-bottom:.5rem; color:var(--color-board-ink-muted); }
 a:focus-visible { outline:2px solid var(--color-focus); outline-offset:-3px; }
 @media(max-width:640px) { .rail { width:100%; } .conversation { display:none; } .in-room .rail { display:none; } .in-room .conversation { display:flex; } .back { display:inline-flex; min-height:44px; align-items:center; color:var(--color-brass-text); font-size:var(--text-sm); } .room-heading { padding:.75rem 1rem; flex-wrap:wrap; } .timeline,.composer { padding:1rem; } }
</style>
