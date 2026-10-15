<script lang="ts">
 import { Button } from '#lib/components/ui/button/index.js';
 import { describeError, type MatrixClient } from '#lib/session.js';
 let { client, term, onPick }: { client: MatrixClient; term: string; onPick: (id: string) => void } = $props();
 let results = $state<{ user_id: string; display_name?: string }[]>([]), error = $state('');
 $effect(() => {
  const query = term.trim().replace(/^@/, '');
  let cancelled = false;
  results = []; error = '';
  if (query.length < 2) return;
  const timer = setTimeout(() => { void client.searchUsers(query).then(r => { if (!cancelled) results = r.results.filter(u => u.user_id !== client.userId); }).catch(e => { if (!cancelled) error = describeError(e); }); }, 250);
  return () => { cancelled = true; clearTimeout(timer); };
 });
</script>
{#if error}<p class="rest-muted">User search is unavailable: {error}</p>{/if}
{#if results.length}<ul class="rest-list" aria-label="Matching people">{#each results as user (user.user_id)}<li><Button variant="ghost" class="h-auto min-h-11 max-w-full whitespace-normal text-left" onclick={() => onPick(user.user_id)}>{user.display_name || user.user_id}{#if user.display_name}<small>{user.user_id}</small>{/if}</Button></li>{/each}</ul>{/if}
