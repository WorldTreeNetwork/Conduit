<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import {
		configuredHomeserver,
		homeserverProblem,
		probeHomeserver,
		type Probe
	} from '#lib/homeserver.js';

	import {
		consumeSsoReturn, beginSso, offersSso, passwordSession, exchangeSso,
		restoreSession, openSession, clearSession, describeError, validateUsername,
		type MatrixClient, type Session
	} from '#lib/session.js';

	// Remove single-use credentials before the component renders, even on rejected returns.
	const ssoReturn = consumeSsoReturn(window);
	const resolved = configuredHomeserver();
	const pinned = resolved.pinned;
	let homeserver = $state(resolved.url);
	let touched = $state(false);
	let checking = $state(false);
	let probe = $state<Probe | null>(null);
	let controller: AbortController | null = null;
	let ssoHomeserver = $state<string | null>(null);
	let username = $state('');
	let password = $state('');
	let signup = $state(false);
	let busy = $state(ssoReturn.state === 'ready');
	let error = $state(ssoReturn.state === 'rejected'
		? 'This tab did not request that sign-in. Try signing in again.' : '');
	let client = $state.raw<MatrixClient | null>(null);
	let displayName = $state('');
	const problem = $derived(homeserverProblem(homeserver));
	const hasSso = $derived(ssoHomeserver === homeserver.trim());
	const fieldError = $derived(
		touched && problem ? problem : probe?.state === 'unreachable' ? probe.message : null
	);

	async function check() {
		touched = true;
		if (problem) return;
		controller?.abort();
		const current = new AbortController();
		controller = current;
		const hs = homeserver.trim();
		checking = true;
		probe = null;
		ssoHomeserver = null;
		try {
			const [answer, sso] = await Promise.all([
				probeHomeserver(hs, current.signal), offersSso(hs).catch(() => false)
			]);
			if (current.signal.aborted || homeserver.trim() !== hs) return;
			probe = answer;
			ssoHomeserver = sso ? hs : null;
		} catch {
			// A changed address superseded this check.
		} finally {
			if (controller === current) checking = false;
		}
	}

	function edited() {
		controller?.abort();
		checking = false;
		probe = null;
		ssoHomeserver = null;
		error = '';
	}

	async function signedIn(session: Session) {
		const next = openSession(session);
		client = next;
		password = '';
		displayName = session.userId;
		try {
			const profile = await next.getProfile(session.userId);
			if (client === next) displayName = profile.displayname || session.userId;
		} catch {
			// A missing profile does not invalidate a successful sign-in.
		}
	}

	async function submitPassword() {
		touched = true;
		error = '';
		if (busy || problem || !username.trim() || !password) return;
		if (signup) {
			const invalid = validateUsername(username);
			if (invalid) { error = invalid; return; }
		}
		busy = true;
		try {
			await signedIn(await passwordSession(homeserver, username, password, signup));
		} catch (err) {
			error = describeError(err);
		} finally {
			busy = false;
		}
	}

	function identikey() {
		if (busy || !hasSso) return;
		try { beginSso(homeserver, window); }
		catch { error = 'Could not start sign-in. Allow tab storage and try again.'; }
	}

	async function signOut() {
		const previous = client;
		busy = true;
		clearSession();
		client = null;
		displayName = '';
		signup = false;
		password = '';
		error = '';
		try { if (previous) await previous.logout(); }
		finally { busy = false; }
	}

	onMount(() => {
		void (async () => {
			if (ssoReturn.state === 'rejected') {
				clearSession();
				return; // No homeserver call for an unsolicited token.
			}
			if (ssoReturn.state === 'ready') {
				clearSession();
				try { await signedIn(await exchangeSso(ssoReturn)); }
				catch { error = 'Sign-in did not finish. The token may have expired or already been used. Try again.'; }
				finally { busy = false; }
			} else {
				const session = restoreSession(homeserver);
				if (session) await signedIn(session);
			}
			if (!client) void check();
		})();
		return () => controller?.abort();
	});
</script>

<svelte:head>
	<title>{client ? `${displayName} · Conduit` : 'Sign in · Conduit'}</title>
</svelte:head>

{#if client}
<main class="mx-auto flex min-h-dvh max-w-5xl flex-col gap-8 p-6">
	<header class="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--color-rule)] pb-5">
		<h1 class="text-2xl">Conduit</h1>
		<div class="flex flex-wrap items-center gap-4">
			<p data-testid="profile-display-name">{displayName}</p>
			<Button variant="outline" onclick={() => void signOut()}>Sign out</Button>
		</div>
	</header>
	<section aria-label="Your session" class="flex flex-col gap-2">
		<h2 class="text-xl">You’re signed in</h2>
		<p class="help">{client.userId}</p>
	</section>
</main>
{:else}
<main class="grid min-h-dvh place-items-center px-4 py-12">
	<div class="plate w-full max-w-[26rem] overflow-hidden">
		<header class="board">
			<span class="lamp" data-state={probe?.state ?? (checking ? 'checking' : 'idle')} aria-hidden="true"
			></span>
			<h1>Conduit</h1>
			<p>Sign in to your homeserver.</p>
		</header>

		<form
			class="flex flex-col gap-5 p-6"
			novalidate
			onsubmit={(e) => {
				e.preventDefault();
				void submitPassword();
			}}
		>
			{#if pinned}
				<div class="flex flex-col gap-1.5">
					<span class="label">Homeserver</span>
					<p class="pinned" data-testid="pinned-homeserver">{homeserver}</p>
					{#if fieldError}
						<p class="error" role="alert">{fieldError}</p>
					{/if}
				</div>
			{:else}
				<div class="flex flex-col gap-1.5">
					<label class="label" for="homeserver">Homeserver</label>
					<Input
						id="homeserver"
						name="homeserver"
						type="url"
						inputmode="url"
						autocomplete="url"
						spellcheck={false}
						bind:value={homeserver}
						oninput={edited}
						onblur={() => void check()}
						disabled={busy}
						aria-invalid={fieldError ? 'true' : undefined}
						aria-describedby="homeserver-help"
						class="h-11 text-base"
					/>
					{#if fieldError}
						<p id="homeserver-help" class="error" role="alert">{fieldError}</p>
					{:else}
						<p id="homeserver-help" class="help">
							The Matrix server that holds your account. Conduit talks to it directly.
						</p>
					{/if}
				</div>
			{/if}

			{#if hasSso}
				<Button type="button" size="lg" class="h-11 text-base" disabled={busy} onclick={identikey}>
					Continue with Identikey
				</Button>
			{/if}
			<div class="flex flex-col gap-1.5">
				<label class="label" for="username">Username</label>
				<Input id="username" name="username" autocomplete="username" bind:value={username} required disabled={busy} class="h-11 text-base" />
			</div>
			<div class="flex flex-col gap-1.5">
				<label class="label" for="password">Password</label>
				<Input id="password" name="password" type="password" autocomplete={signup ? 'new-password' : 'current-password'} bind:value={password} required disabled={busy} class="h-11 text-base" />
			</div>
			{#if error}<p class="error" role="alert">{error}</p>{/if}
			<div class="flex flex-col gap-3">
				<Button type="submit" variant={hasSso ? 'outline' : 'default'} size="lg" class="h-11 text-base" disabled={busy || !username.trim() || !password}>
					{busy ? 'Please wait…' : signup ? 'Create account' : 'Sign in with password'}
				</Button>
				<Button type="button" variant="ghost" disabled={busy} onclick={() => { signup = !signup; error = ''; }}>
					{signup ? 'Already have an account? Sign in' : 'Create an account'}
				</Button>
				<p class="status" aria-live="polite">
					{#if checking}Checking homeserver…
					{:else if probe?.state === 'ok'}Homeserver is answering (Matrix {probe.versions.at(-1)}).{/if}
				</p>
			</div>
		</form>
	</div>
</main>
{/if}

<style>
	.plate {
		background: var(--color-surface);
		border: 1px solid var(--color-rule);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-plate);
	}

	.board {
		display: grid;
		grid-template-columns: auto 1fr;
		column-gap: var(--space-3);
		align-items: center;
		padding: var(--space-5) var(--space-6);
		background: var(--color-board);
		color: var(--color-board-ink);
	}

	.board h1 {
		font-size: var(--text-2xl);
		letter-spacing: -0.01em;
	}

	.board p {
		grid-column: 2;
		color: var(--color-board-ink-muted);
		font-size: var(--text-sm);
	}

	.lamp {
		width: 0.625rem;
		height: 0.625rem;
		border-radius: var(--radius-pill);
		background: var(--color-board-rule);
		transition:
			background var(--duration-med) var(--ease-out),
			box-shadow var(--duration-med) var(--ease-out);
	}
	.lamp[data-state='checking'] {
		background: var(--color-lamp);
		box-shadow: 0 0 0 4px var(--color-lamp-halo);
	}
	.lamp[data-state='ok'] {
		background: var(--color-board-clear);
		box-shadow: 0 0 0 4px var(--color-clear-halo);
	}
	.lamp[data-state='unreachable'] {
		background: var(--color-board-signal);
		box-shadow: 0 0 0 4px var(--color-signal-halo);
	}

	.label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--color-ink);
	}

	.pinned {
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-md);
		background: var(--color-surface-sunk);
		color: var(--color-ink);
		overflow-wrap: anywhere;
	}

	.help,
	.status {
		font-size: var(--text-sm);
		color: var(--color-ink-muted);
	}

	.status:empty {
		display: none;
	}

	.error {
		font-size: var(--text-sm);
		color: var(--color-signal-ink);
	}
</style>
