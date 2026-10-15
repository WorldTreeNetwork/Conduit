// Password login and password confirmation in the UI.
// The protocol core always speaks m.login.password. The pages do not,
// unless this build sets VITE_CONDUIT_PASSWORD to 1, true, on, or yes.

const ENABLED = new Set(['1', 'true', 'on', 'yes']);

export function passwordLoginEnabled(raw?: string | null): boolean {
	const value = (raw ?? readBuildFlag()).trim().toLowerCase();
	return ENABLED.has(value);
}

function readBuildFlag(): string {
	const env = import.meta.env as { VITE_CONDUIT_PASSWORD?: string } | undefined;
	return env?.VITE_CONDUIT_PASSWORD ?? '';
}
