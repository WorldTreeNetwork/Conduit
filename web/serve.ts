// Static file server for the built client. mj deploy listens on PORT.
// Unknown paths fall back to index.html so client routes survive a refresh.
// Directory names named `build` are stripped from the deploy tarball, so this
// file serves the tree the guest build step writes at /app/build.
//
// conduit-web.vm.worldtree.network redirects to conduit.worldtree.network.
// Matrix paths on the public origin are proxied to the homeserver, which
// stays reachable at CONDUIT_UPSTREAM (conduit.vm.worldtree.network).

import { legacyRedirect, proxyToHomeserver } from './src/lib/public-host.ts';

const root = `${import.meta.dir}/build`;
const port = Number(process.env.PORT ?? '8080');
const hostname = process.env.HOST ?? '0.0.0.0';
const upstream = (process.env.CONDUIT_UPSTREAM ?? 'https://conduit.vm.worldtree.network').replace(/\/+$/, '');

function relativePath(pathname: string): string | null {
	let decoded: string;
	try {
		decoded = decodeURIComponent(pathname);
	} catch {
		return null;
	}
	if (decoded.includes('\0') || decoded.split('/').includes('..')) return null;
	return decoded.replace(/^\/+/, '');
}

async function fileResponse(path: string): Promise<Response | null> {
	const file = Bun.file(path);
	if (!(await file.exists())) return null;
	if (!(await file.stat()).isFile()) return null;
	return new Response(file);
}

async function proxy(req: Request, url: URL): Promise<Response> {
	const headers = new Headers(req.headers);
	headers.delete('host');
	const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : req.body;
	const upstreamResponse = await fetch(`${upstream}${url.pathname}${url.search}`, {
		method: req.method,
		headers,
		body,
		redirect: 'manual',
		// Bun requires duplex when a request body is a stream.
		...(body ? { duplex: 'half' as const } : {}),
	});
	const responseHeaders = new Headers(upstreamResponse.headers);
	responseHeaders.delete('transfer-encoding');
	return new Response(upstreamResponse.body, {
		status: upstreamResponse.status,
		statusText: upstreamResponse.statusText,
		headers: responseHeaders,
	});
}

Bun.serve({
	hostname,
	port,
	async fetch(req) {
		const url = new URL(req.url);
		const redirect = legacyRedirect(req.headers.get('host'), `${url.pathname}${url.search}`);
		if (redirect) return Response.redirect(redirect, 308);
		if (proxyToHomeserver(url.pathname)) return proxy(req, url);

		const relative = relativePath(url.pathname);
		if (relative === null) return new Response('bad path', { status: 400 });

		if (relative !== '') {
			const exact = await fileResponse(`${root}/${relative}`);
			if (exact) return exact;
			const nested = await fileResponse(`${root}/${relative}/index.html`);
			if (nested) return nested;
		}

		const index = await fileResponse(`${root}/index.html`);
		if (index) return index;
		return new Response('client build missing', { status: 503 });
	},
});

console.log(`conduit-web listening on ${hostname}:${port}`);
