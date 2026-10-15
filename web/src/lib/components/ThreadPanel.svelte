<script lang="ts">
 import { tick } from 'svelte';
 import { Button } from '#lib/components/ui/button/index.js';
 import { Input } from '#lib/components/ui/input/index.js';
 import { describeError, relatesTo, type MatrixClient, type Room } from '#lib/session.js';
 import Message from './Message.svelte';
 import Media from './Media.svelte';
 let { client, room, rootId, version }: { client: MatrixClient; room: Room; rootId: string; version: number } = $props();
 let loading = $state(true), error = $state(''), draft = $state(''), attempt = $state(0);
 let input = $state<HTMLInputElement | null>(null);
 const roomId = $derived(room.roomId);
 $effect(() => {
  // Depend on the id string. Reading the room object re-runs this effect on every
  // sync version, and loadThread emits synchronously, which loops until Svelte stops the page.
  const id = rootId, target = roomId; attempt;
  let cancelled = false;
  loading = true; error = ''; draft = '';
  void client.loadThread(target, id).catch(e => { if (!cancelled) error = describeError(e); }).finally(() => { if (!cancelled) loading = false; });
  void tick().then(() => { if (!cancelled) input?.focus(); });
  return () => { cancelled = true; };
 });
 const root = $derived.by(() => { version; return room.findEvent(rootId); });
 const replies = $derived.by(() => { version; return room.threadReplies(rootId, client.userId); });
 const pending = $derived.by(() => {
  version;
  return client.sendQueue.forRoom(room.roomId).filter(p => relatesTo(p).relType === 'm.thread' && relatesTo(p).eventId === rootId && (!p.eventId || !room.findEvent(p.eventId))).map(p => ({
   txnId: p.txnId, status: p.status, error: p.error, body: String(p.content.body ?? ''), image: p.content.msgtype === 'm.image', content: p.content, localUrl: p.attachment?.localUrl
  }));
 });
 function send() { if (!draft.trim()) return; client.sendThreadMessage(room.roomId, rootId, draft.trim()); draft = ''; client.setTyping(room.roomId, false); }
</script>
<div data-testid="thread-panel" data-root-id={rootId}>
 <div role="log" aria-label="Thread messages" aria-live="polite">
  {#if root}<Message {client} {room} event={root} {version} />{/if}
  {#if loading && !replies.length}<p role="status">Loading replies…</p>{/if}
  {#if error}<p class="rest-error" role="alert">Couldn't load this thread. {error} <Button variant="outline" onclick={() => attempt++}>Try again</Button></p>{/if}
  {#if !loading && !error && !replies.length && !pending.length}<p class="rest-muted">No replies yet. Start the thread below.</p>{/if}
  {#each replies as event (event.event_id)}<Message {client} {room} {event} {version} />{/each}
  {#each pending as message (message.txnId)}<article class="rest-message" data-txn-id={message.txnId}><div class="rest-message-body"><div class="rest-byline"><strong>{room.memberName(client.userId)}</strong><span>{message.status === 'failed' ? 'Not sent' : 'Sending…'}</span></div>{#if message.image}<Media {client} content={message.content} localUrl={message.localUrl} />{:else}<p>{message.body}</p>{/if}{#if message.status === 'failed'}<p class="rest-error">{message.error}</p><Button variant="outline" onclick={() => client.retrySend(message.txnId)}>Retry</Button>{/if}</div></article>{/each}
 </div>
 <form class="rest-stack thread-composer" onsubmit={e => { e.preventDefault(); send(); }}><label for="thread-message">Reply in thread</label><Input id="thread-message" bind:ref={input} bind:value={draft} autocomplete="off" oninput={e => client.setTyping(room.roomId, !!e.currentTarget.value.trim())} onblur={() => client.setTyping(room.roomId, false)} /><Button type="submit" disabled={!draft.trim()}>Send reply</Button></form>
</div>
<style>.thread-composer { border-top:1px solid var(--color-rule); padding-top:1rem; margin-top:1rem; }</style>
