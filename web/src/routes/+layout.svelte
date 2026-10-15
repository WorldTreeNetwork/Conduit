<script lang="ts">
	import './layout.css';
	import { onMount } from 'svelte';
	import { applyTheme, loadTheme } from '#lib/theme.js';
	import favicon from '#lib/assets/favicon.svg';
	import type { LayoutProps } from './$types';

	onMount(() => applyTheme(loadTheme()));

	let { children }: LayoutProps = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

{@render children()}
