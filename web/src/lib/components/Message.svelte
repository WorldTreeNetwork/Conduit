<script lang="ts">
 import * as Avatar from '#lib/components/ui/avatar/index.js';
 import { Button } from '#lib/components/ui/button/index.js';
 import { type MatrixClient, type Room, type MatrixEvent, type JsonObject } from '#lib/session.js';
 import Media from './Media.svelte';
 let { client, room, event, version, openThread }: { client: MatrixClient; room: Room; event: MatrixEvent; version: number; openThread?: (id: string) => void } = $props();
 const relations = $derived.by(() => { version; return room.aggregations(client.userId); });
 const removed = $derived.by(() => { version; return !!event.unsigned?.redacted_because; });
 const content = $derived((relations.edits.get(event.event_id)?.content['m.new_content'] as JsonObject | undefined) ?? event.content);
 const sender = $derived.by(() => { version; return room.memberName(event.sender); });
 const thread = $derived(relations.threads.get(event.event_id));
</script>
<article class="rest-message" data-event-id={event.event_id}>
 <Avatar.Root class="size-9"><Avatar.Fallback class="nameplate">{sender.replace('@', '').slice(0, 2).toUpperCase()}</Avatar.Fallback></Avatar.Root>
 <div class="rest-message-body"><div class="rest-byline"><strong>{sender}</strong><time datetime={new Date(event.origin_server_ts).toISOString()}>{new Date(event.origin_server_ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time></div>
  {#if removed}<p>Message removed</p>{:else if ['m.image', 'm.file', 'm.audio', 'm.video'].includes(String(content.msgtype))}<Media {client} {content} />{:else}<p>{String(content.body ?? 'Unsupported message')}</p>{/if}
  {#if openThread && !removed}<Button variant="ghost" class="thread-action" aria-label={thread?.count ? `Open thread, ${thread.count} replies` : 'Start thread'} onclick={() => openThread?.(event.event_id)}>{thread?.count ? `${thread.count} ${thread.count === 1 ? 'reply' : 'replies'}` : 'Reply in thread'}</Button>{/if}
 </div>
</article>
