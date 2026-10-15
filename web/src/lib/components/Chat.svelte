<script lang="ts">
 import { onMount, tick, untrack } from 'svelte';
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import * as Dialog from '#lib/components/ui/dialog/index.js';
 import { ScrollArea } from '#lib/components/ui/scroll-area/index.js';
 import * as Avatar from '#lib/components/ui/avatar/index.js';
 import { describeError, type MatrixClient } from '#lib/session.js';
 let { client, displayName, signOut }: { client: MatrixClient; displayName: string; signOut: () => void } = $props();
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
   name: room.displayName(client.userId), topic: room.topic, exhausted: room.historyExhausted,
   messages: room.timeline.filter(e => e.type === 'm.room.message' && !relations.hidden.has(e.event_id)).map(e => {
    const replacement = relations.edits.get(e.event_id)?.content['m.new_content'] as { body?: unknown } | undefined;
    return { id: e.event_id, sender: room.member(e.sender)?.displayName ?? e.sender, ts: e.origin_server_ts,
     body: e.unsigned?.redacted_because ? 'Message removed' : String(replacement?.body ?? e.content.body ?? 'Unsupported message') };
   }),
   pending: client.sendQueue.forRoom(room.roomId).filter(e => e.type === 'm.room.message' && (!e.eventId || !room.hasEvent(e.eventId))).map(e => ({ txnId: e.txnId, status: e.status, error: e.error, body: String(e.content.body ?? '') }))
  };
 });
 function readHash() {
  const match = /^#\/room\/(.+)$/.exec(location.hash);
  try { selected = match ? decodeURIComponent(match[1]) : null; }
  catch { selected = null; location.replace('#/'); }
  historyError = '';
 }
 function home() { location.hash = '#/'; selected = null; }
 function roomRoute(id: string) { location.hash = `#/room/${encodeURIComponent(id)}`; selected = id; }
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
  client.sendMessage(selected, drafts[selected].trim()); drafts[selected] = '';
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
  const id = selected, last = view?.pending.at(-1)?.txnId ?? view?.messages.at(-1)?.id;
  if (id !== previousRoom || (last !== previousLast && nearBottom)) {
   void tick().then(() => { if (selected === id && viewport) viewport.scrollTop = viewport.scrollHeight; });
  }
  previousRoom = id; previousLast = last;
 });
</script>

<svelte:window onfocus={() => { if (selected) void client.markRead(selected); }} />
<main class="chat" class:in-room={!!selected}>
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
  <footer><Button variant="outline" onclick={signOut}>Sign out</Button></footer>
 </aside>
 <section class="conversation" aria-label={view?.name ?? 'Home'}>
  {#if view}
   <header class="room-heading"><a class="back" href="#/">← Rooms</a><div><h1>{view.name}</h1>{#if view.topic}<p>{view.topic}</p>{/if}</div><Button variant="outline" onclick={() => show('invite')}>Invite</Button></header>
   <ScrollArea class="min-h-0 flex-1" bind:viewportRef={viewport} onscrollcapture={() => { if (viewport) nearBottom = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 100; }}>
    <div class="timeline" role="log" aria-label="Messages" aria-live="polite" aria-relevant="additions">
     <div class="history">{#if !view.exhausted}<Button variant="ghost" disabled={paging} onclick={() => void history()}>{paging ? 'Loading history…' : 'Load older messages'}</Button>{:else}<p>Beginning of conversation</p>{/if}{#if historyError}<p class="error" role="alert">{historyError}</p>{/if}</div>
     {#each view.messages as message (message.id)}
      <article class="message" data-event-id={message.id}><Avatar.Root class="size-9"><Avatar.Fallback class="nameplate">{message.sender.replace('@', '').slice(0, 2).toUpperCase()}</Avatar.Fallback></Avatar.Root><div class="message-content"><div class="byline"><strong>{message.sender}</strong><time datetime={new Date(message.ts).toISOString()}>{new Date(message.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time></div><p>{message.body}</p></div></article>
     {/each}
     {#each view.pending as message (message.txnId)}
      <article class="message pending" data-txn-id={message.txnId}><Avatar.Root class="size-9"><Avatar.Fallback class="nameplate">{displayName.replace('@', '').slice(0, 2).toUpperCase()}</Avatar.Fallback></Avatar.Root><div class="message-content"><div class="byline"><strong>{displayName}</strong><span>{message.status === 'failed' ? 'Not sent' : message.status === 'sent' ? 'Sent · awaiting sync' : 'Sending…'}</span></div><p>{message.body}</p>{#if message.status === 'failed'}<p class="error">{message.error}</p><Button variant="outline" onclick={() => client.retrySend(message.txnId)}>Retry</Button>{/if}</div></article>
     {/each}
     {#if !view.messages.length && !view.pending.length}<p class="empty-thread">A new conversation. Send the first message.</p>{/if}
    </div>
   </ScrollArea>
   <form class="composer" onsubmit={e => { e.preventDefault(); send(); }}><label for="message">Message {view.name}</label><div><Input id="message" name="message" autocomplete="off" bind:value={drafts[selected!]} placeholder="Write a message…" class="h-11 min-w-0" /><Button type="submit" class="h-11" disabled={!selected || !drafts[selected]?.trim()}>Send</Button></div></form>
  {:else}<div class="home"><span class="eyebrow">Your conversations</span><h1>A place to catch up.</h1><p>Choose a room, or start a conversation with someone.</p><div><Button onclick={() => show('create')}>Create room</Button><Button variant="outline" onclick={() => show('join')}>Join room</Button></div></div>{/if}
  {#if error && !open}<p class="error action-error" role="alert">{error}</p>{/if}
 </section>
</main>
<Dialog.Root bind:open>
 <Dialog.Content onCloseAutoFocus={e => { e.preventDefault(); dialogTrigger?.focus(); }} showCloseButton={!working} onInteractOutside={e => { if (working) e.preventDefault(); }} onEscapeKeydown={e => { if (working) e.preventDefault(); }}>
  <Dialog.Header><Dialog.Title>{dialog === 'create' ? 'Create room' : dialog === 'join' ? 'Join room' : 'Invite someone'}</Dialog.Title><Dialog.Description>{dialog === 'create' ? 'Start a private conversation. You can invite people next.' : dialog === 'join' ? 'Enter a room ID or alias, including its homeserver.' : `Invite a Matrix account to ${view?.name ?? 'this room'}.`}</Dialog.Description></Dialog.Header>
  <form class="dialog-form" onsubmit={e => { e.preventDefault(); void submit(); }}><label for="room-field">{dialog === 'create' ? 'Room name' : dialog === 'join' ? 'Room ID or alias' : 'Matrix user ID'}</label><Input id="room-field" bind:value={field} disabled={working} required placeholder={dialog === 'create' ? 'Weekend plans' : dialog === 'join' ? '#room:example.org' : '@person:example.org'} />{#if error}<p class="error" role="alert">{error}</p>{/if}<Dialog.Footer><Button type="button" variant="outline" disabled={working} onclick={() => { open = false; }}>Cancel</Button><Button type="submit" disabled={working || !field.trim()}>{working ? 'Please wait…' : dialog === 'create' ? 'Create room' : dialog === 'join' ? 'Join room' : 'Send invitation'}</Button></Dialog.Footer></form>
 </Dialog.Content>
</Dialog.Root>

<style>
 .chat { display:flex; height:100dvh; overflow:hidden; }
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
 .room-heading div { min-width:0; flex:1; }
 .room-heading h1 { font-size:var(--text-xl); overflow-wrap:anywhere; }
 .room-heading p { color:var(--color-ink-muted); font-size:var(--text-sm); overflow-wrap:anywhere; }
 .back { display:none; }
 .timeline { max-width:54rem; margin:auto; padding:1rem 2rem 2rem; }
 .history { text-align:center; color:var(--color-ink-muted); font-size:var(--text-sm); padding-bottom:1.5rem; }
 .message { display:flex; gap:.75rem; padding:.75rem 0; }
 .message-content { min-width:0; flex:1; }
 .byline { display:flex; gap:.75rem; align-items:baseline; flex-wrap:wrap; }
 .byline strong { font-size:var(--text-sm); overflow-wrap:anywhere; }
 .byline time,.byline span { font-size:var(--text-xs); color:var(--color-ink-muted); }
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
