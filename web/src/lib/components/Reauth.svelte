<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { passwordLoginEnabled } from '#lib/password.js';
	import { beginSso, describeError, offersSso, type MatrixClient } from '#lib/session.js';

	const passwords = passwordLoginEnabled();
	let { client, signOut }: { client: MatrixClient; signOut: () => void } = $props();
	let offered = $state(false);
	let password = $state('');
	let error = $state('');
	let pending = $state(false);

	async function submitPassword() {
		if (!passwords || !password || pending) return;
		pending = true;
		error = '';
		try { await client.reauthenticate(password); }
		catch (e) { error = describeError(e); }
		finally { pending = false; password = ''; }
	}

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
		{:else if !passwords}
			<p>Identikey sign-in is turned off, so this page cannot sign you back in. Ask the person who runs the homeserver to turn it on.</p>
		{/if}
		{#if passwords}
			<form class="rest-stack" onsubmit={(e) => { e.preventDefault(); void submitPassword(); }}>
				<label for="reauth-password">Password</label>
				<Input id="reauth-password" type="password" autocomplete="current-password" bind:value={password} required disabled={pending} />
				<Button type="submit" disabled={pending || !password}>{pending ? 'Signing in…' : 'Continue'}</Button>
			</form>
		{/if}
		{#if error}<p class="rest-error" role="alert">{error}</p>{/if}
		<Button variant="outline" onclick={signOut}>Sign out instead</Button>
	</div>
</main>

<style>
	.reauth { min-height: 100dvh; display: grid; place-items: center; padding: 1.5rem; }
	.reauth > div { max-width: 28rem; padding: 1.5rem; border: 1px solid var(--color-rule); background: var(--color-surface); border-radius: var(--radius-lg); }
	h1 { font-size: var(--text-2xl); }
</style>
