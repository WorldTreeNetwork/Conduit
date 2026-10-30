// Public names for the hosted client. The Matrix server name is
// conduit.worldtree.network. The old web host stays up and redirects there.

export const CANONICAL_ORIGIN = 'https://conduit.worldtree.network';
export const LEGACY_WEB_HOST = 'conduit-web.vm.worldtree.network';

export function hostnameOf(hostHeader: string | null): string {
	return (hostHeader ?? '').trim().replace(/:\d+$/, '').toLowerCase();
}

export function legacyRedirect(hostHeader: string | null, pathAndQuery: string): string | null {
	if (hostnameOf(hostHeader) !== LEGACY_WEB_HOST) return null;
	return CANONICAL_ORIGIN + (pathAndQuery.startsWith('/') ? pathAndQuery : `/${pathAndQuery}`);
}

/** Paths the browser calls on the public origin that the homeserver owns. */
export function proxyToHomeserver(pathname: string): boolean {
	return (
		pathname === '/_matrix' ||
		pathname.startsWith('/_matrix/') ||
		pathname.startsWith('/.well-known/matrix/')
	);
}
