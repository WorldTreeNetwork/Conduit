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

	const resolved = configuredHomeserver();
	const pinned = resolved.pinned;

	let homeserver = $state(resolved.url);
	let touched = $state(false);
	let checking = $state(false);
	let probe = $state<Probe | null>(null);
	let controller: AbortController | null = null;

	const problem = $derived(homeserverProblem(homeserver));
	const fieldError = $derived(
		touched && problem ? problem : probe?.state === 'unreachable' ? probe.message : null
	);

	async function check() {
		touched = true;
		if (problem) return;
		controller?.abort();
		controller = new AbortController();
		checking = true;
		probe = null;
		try {
			probe = await probeHomeserver(homeserver, controller.signal);
		} catch {
			return; // superseded by a newer check
		} finally {
			checking = false;
		}
	}

	function edited() {
		probe = null;
	}

	onMount(() => {
		if (pinned) void check();
		return () => controller?.abort();
	});
</script>

<svelte:head>
	<title>Sign in · Conduit</title>
</svelte:head>

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
				void check();
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
						onblur={() => (touched = true)}
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

			<div class="flex flex-col gap-3">
				<Button type="submit" size="lg" class="h-11 text-base" disabled={checking}>
					{checking ? 'Checking homeserver…' : 'Continue'}
				</Button>
				<p class="status" aria-live="polite">
					{#if probe?.state === 'ok'}
						Homeserver is answering (Matrix {probe.versions.at(-1)}).
					{/if}
				</p>
			</div>
		</form>
	</div>
</main>

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
