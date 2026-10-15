<script lang="ts">
 import Presence from './Presence.svelte';
 import type { MatrixClient, Room } from '#lib/session.js';
 let { client, room, version }: { client: MatrixClient; room: Room; version: number } = $props();
 const members = $derived.by(() => { version; return room.members().sort((a,b) => room.powerLevel(b.userId) - room.powerLevel(a.userId) || room.memberName(a.userId).localeCompare(room.memberName(b.userId))); });
</script>
{#each ['join', 'invite'] as membership}
 {@const group = members.filter(m => m.membership === membership)}
 {#if group.length}<section class="rest-section"><h3>{membership === 'join' ? 'In the room' : 'Invited'} · {group.length}</h3><ul class="rest-list" data-testid={membership === 'join' ? 'joined-members' : 'invited-members'}>
  {#each group as member (member.userId)}<li data-testid="member-row" data-user-id={member.userId} data-membership={membership}><div><strong>{room.memberName(member.userId)}{member.userId === client.userId ? ' (you)' : ''}</strong><small>{member.userId}</small>{#if membership === 'join'}<Presence {client} userId={member.userId} {version} />{/if}</div>{#if room.powerLevel(member.userId) >= 50}<span class="rest-badge">{room.powerLevel(member.userId) >= 100 ? 'Admin' : 'Moderator'}</span>{/if}</li>{/each}
 </ul></section>{/if}
{/each}
