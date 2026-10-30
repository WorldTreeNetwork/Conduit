<script lang="ts">
	import { describeError, type MatrixClient, type RoomListEntry } from '#lib/session.js';

	let {
		client,
		version,
		entries,
		selected,
		working,
		onAccept,
	}: {
		client: MatrixClient;
		version: number;
		entries: RoomListEntry[];
		selected: string | null;
		working: boolean;
		onAccept: (roomId: string) => void;
	} = $props();

	let invitationsOpen = $state(true);
	let starredOpen = $state(true);
	let roomsOpen = $state(true);
	let marking = $state('');
	let markError = $state('');

	const rows = $derived.by(() => {
		version;
		return entries.map((entry) => {
			const room = client.getRoom(entry.roomId);
			const isPublic = room?.isPublic ?? false;
			const marked = room?.marked ?? false;
			const invite = entry.membership === 'invite';
			return { entry, isPublic, marked, invite };
		});
	});
	const invitations = $derived(rows.filter((row) => row.invite));
	const joined = $derived(rows.filter((row) => !row.invite));
	const starred = $derived(joined.filter((row) => row.marked));

	function kindLabel(row: (typeof rows)[number]): string {
		if (row.invite) return row.isPublic ? 'Invitation to a public room' : 'Invitation to a private room';
		if (row.marked && row.isPublic) return 'Marked public room';
		if (row.marked) return 'Marked private room';
		return row.isPublic ? 'Public room' : 'Private room';
	}

	async function toggleMark(roomId: string, marked: boolean) {
		marking = roomId;
		markError = '';
		try {
			await client.setMarked(roomId, marked);
		} catch (error) {
			markError = describeError(error);
		} finally {
			marking = '';
		}
	}
</script>

{#snippet hash()}
	<svg class="glyph" viewBox="0 0 20 20" aria-hidden="true">
		<path d="M8 3.5 6.6 16.5M13.4 3.5 12 16.5M3.5 7.5h13M3 12.5h13" />
	</svg>
{/snippet}

{#snippet lock()}
	<svg class="glyph" viewBox="0 0 20 20" aria-hidden="true">
		<rect x="4" y="9" width="12" height="8" rx="1.5" />
		<path d="M7 9V6.5a3 3 0 0 1 6 0V9" />
	</svg>
{/snippet}

{#snippet star(filled: boolean)}
	<svg class="glyph star" viewBox="0 0 20 20" aria-hidden="true">
		<path
			d="m10 2.8 2.1 4.3 4.7.7-3.4 3.3.8 4.7L10 13.6 5.8 15.8l.8-4.7L3.2 7.8l4.7-.7L10 2.8Z"
			fill={filled ? 'currentColor' : 'none'}
		/>
	</svg>
{/snippet}

{#snippet row(row: (typeof rows)[number])}
	{@const entry = row.entry}
	{@const active = selected === entry.roomId}
	{@const unread = entry.unread > 0}
	<div class="room-row" class:active class:unread class:invite={row.invite} class:marked={row.marked}>
		{#if row.invite}
			<div class="room-main" aria-label="{kindLabel(row)}, {entry.name}">
				<span class="icon invite" role="img" aria-label={row.isPublic ? 'Public invitation' : 'Private invitation'}>
					{#if row.isPublic}{@render hash()}{:else}{@render lock()}{/if}
				</span>
				<span class="room-name">{entry.name}</span>
				<span class="sr-only">{entry.inviter ? `From ${entry.inviter}` : 'Pending invitation'}</span>
			</div>
			<button type="button" class="accept" aria-label="Accept invitation" disabled={working} onclick={() => onAccept(entry.roomId)}>Join</button>
		{:else}
			<a
				class="room-main"
				href={`#/room/${encodeURIComponent(entry.roomId)}`}
				aria-current={active ? 'page' : undefined}
				aria-label="{kindLabel(row)}, {entry.name}"
			>
				<span class="icon" class:public={row.isPublic} title={row.isPublic ? 'Public room' : 'Private room'}>
					{#if row.isPublic}{@render hash()}{:else}{@render lock()}{/if}
				</span>
				<span class="room-name">{entry.name}</span>
				{#if entry.highlights > 0}<span class="count mention" aria-label={`${entry.highlights} mentions`}>{entry.highlights}</span>
				{:else if unread}<span class="count" aria-label={`${entry.unread} unread`}>{entry.unread}</span>{/if}
			</a>
			<button
				type="button"
				class="mark"
				class:on={row.marked}
				aria-pressed={row.marked}
				aria-label={row.marked ? `Unmark ${entry.name}` : `Mark ${entry.name}`}
				disabled={marking === entry.roomId}
				onclick={() => void toggleMark(entry.roomId, !row.marked)}
			>{@render star(row.marked)}</button>
		{/if}
	</div>
{/snippet}

{#snippet section(title: string, open: boolean, toggle: () => void, items: typeof rows)}
	{#if items.length}
		<section>
			<button type="button" class="section" aria-expanded={open} onclick={toggle}>
				<svg class="chevron" class:shut={!open} viewBox="0 0 20 20" aria-hidden="true"><path d="m5 7 5 6 5-6" /></svg>
				{title}
			</button>
			{#if open}
				<div class="section-rows">{#each items as item (item.entry.roomId)}{@render row(item)}{/each}</div>
			{/if}
		</section>
	{/if}
{/snippet}

<nav class="list" aria-label="Rooms">
	{@render section('Invitations', invitationsOpen, () => (invitationsOpen = !invitationsOpen), invitations)}
	{@render section('Starred', starredOpen, () => (starredOpen = !starredOpen), starred)}
	<section>
		<button type="button" class="section" aria-expanded={roomsOpen} onclick={() => (roomsOpen = !roomsOpen)}>
			<svg class="chevron" class:shut={!roomsOpen} viewBox="0 0 20 20" aria-hidden="true"><path d="m5 7 5 6 5-6" /></svg>
			Rooms
		</button>
		{#if roomsOpen}
			<div class="section-rows">
				{#each joined as item (item.entry.roomId)}{@render row(item)}{:else}<p class="empty">Rooms you join or get invited to show up here.</p>{/each}
			</div>
		{/if}
	</section>
	{#if markError}<p class="mark-error" role="alert">{markError}</p>{/if}
</nav>

<style>
	.list {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		padding: 0.25rem 0 0.75rem;
		color: #f4f4f5;
	}
	.section {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		width: calc(100% - 1rem);
		margin: 0.75rem 0.5rem 0.15rem;
		padding: 0.15rem 0.4rem;
		border: 0;
		border-radius: 6px;
		background: transparent;
		color: #c6c6cf;
		font: inherit;
		font-size: 0.8125rem;
		font-weight: 700;
		text-align: left;
		cursor: pointer;
	}
	.section:hover {
		background: rgb(255 255 255 / 0.06);
	}
	.chevron {
		width: 0.85rem;
		height: 0.85rem;
		fill: none;
		stroke: currentColor;
		stroke-width: 1.75;
		stroke-linecap: round;
		stroke-linejoin: round;
	}
	.chevron.shut {
		transform: rotate(-90deg);
	}
	.section-rows {
		display: flex;
		flex-direction: column;
		gap: 1px;
	}
	.room-row {
		display: flex;
		align-items: center;
		gap: 0.15rem;
		margin: 0 0.5rem;
		border-radius: 6px;
		min-height: 1.75rem;
	}
	.room-row:hover,
	.room-row:focus-within {
		background: rgb(255 255 255 / 0.08);
	}
	.room-row.active {
		background: rgb(16 221 224 / 0.18);
	}
	.room-main {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		min-width: 0;
		flex: 1;
		padding: 0.2rem 0.15rem 0.2rem 0.45rem;
		color: #c6c6cf;
		text-decoration: none;
	}
	.room-row.unread .room-name,
	.room-row.invite .room-name {
		color: #fff;
		font-weight: 700;
	}
	.room-row.active .room-name {
		color: #fff;
	}
	.room-name {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.9375rem;
		line-height: 1.3;
	}
	.icon {
		display: grid;
		flex: none;
		place-items: center;
		width: 1.15rem;
		color: #b7b7c2;
	}
	.room-row.active .icon,
	.icon.public,
	.icon.invite {
		color: #10dde0;
	}
	.glyph {
		width: 0.95rem;
		height: 0.95rem;
		fill: none;
		stroke: currentColor;
		stroke-width: 1.6;
		stroke-linecap: round;
		stroke-linejoin: round;
	}
	.count {
		margin-left: auto;
		min-width: 1.25rem;
		padding: 0 0.35rem;
		border-radius: 999px;
		background: #f4f4f5;
		color: #212026;
		font-size: 0.75rem;
		font-variant-numeric: tabular-nums;
		font-weight: 700;
		line-height: 1.25rem;
		text-align: center;
	}
	.count.mention {
		background: #de3627;
		color: #fff;
	}
	.mark {
		display: grid;
		flex: none;
		place-items: center;
		width: 1.5rem;
		height: 1.5rem;
		margin-right: 0.15rem;
		border: 0;
		border-radius: 4px;
		background: transparent;
		color: #c6c6cf;
		cursor: pointer;
	}
	@media (hover: hover) and (pointer: fine) {
		.mark { opacity: 0; }
		.room-row:hover .mark,
		.room-row:focus-within .mark,
		.mark.on { opacity: 1; }
	}
	.mark.on {
		color: #10dde0;
	}
	.mark:hover {
		background: rgb(255 255 255 / 0.08);
	}
	.accept {
		flex: none;
		margin-right: 0.25rem;
		padding: 0.1rem 0.4rem;
		border: 0;
		border-radius: 4px;
		background: #10dde0;
		color: #062426;
		font: inherit;
		font-size: 0.75rem;
		font-weight: 700;
		cursor: pointer;
	}
	.accept:disabled {
		opacity: 0.6;
	}
	.empty,
	.mark-error {
		margin: 0.25rem 1rem 0.5rem;
		color: #c6c6cf;
		font-size: 0.8125rem;
	}
	.mark-error {
		color: #ffb4ab;
	}
	.section:focus-visible,
	.room-main:focus-visible,
	.mark:focus-visible,
	.accept:focus-visible {
		outline: 2px solid #10dde0;
		outline-offset: 1px;
	}
</style>
