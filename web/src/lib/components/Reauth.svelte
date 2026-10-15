<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { beginSso, offersSso, type MatrixClient } from '#lib/session.js';

	let { client, signOut }: { client: MatrixClient; signOut: () => void } = $props();
	let offered = $state(false);
	let error = $state('');

	onMount(() => {
		void offersSso(client.session.homeserverUrl).then((yes) => { offered = yes; }).catch(() => { offered = false; });
	});

	function identikey() {
		try { beginSso(client.session.homeserverUrl, window); }
		catch { error = 'Could not start sign-in. Allow tab storage and try again.'; }
	}
</script>

<main class="reauth">
	<div class="rest-stack">
		<h1>Your session expired</h1>
		<p>Sign in again as <strong>{client.userId}</strong> to continue on this device. Your rooms and unsent messages are kept.</p>
		{#if offered}
			<Button type="button" onclick={identikey}>Continue with Identikey</Button>
		{:else}
			<p>This homeserver is not offering Identikey.</p>
		{/if}
		{#if error}<p class="rest-error" role="alert">{error}</p>{/if}
		<p>A key you hold signs in through the Identikey wallet.</p>
		<Button variant="outline" onclick={signOut}>Sign out instead</Button>
	</div>
</main>

<style>
	.reauth { min-height: 100dvh; display: grid; place-items: center; padding: 1.5rem; }
	.reauth > div { max-width: 28rem; padding: 1.5rem; border: 1px solid var(--color-rule); background: var(--color-surface); border-radius: var(--radius-lg); }
	h1 { font-size: var(--text-2xl); }
</style>
