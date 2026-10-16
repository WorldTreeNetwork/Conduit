// Static file server for the built client. mj deploy listens on PORT.
// Unknown paths fall back to index.html so client routes survive a refresh.
// Directory names named `build` are stripped from the deploy tarball, so this
// file serves the tree the guest build step writes at /app/build.

const root = `${import.meta.dir}/build`;
const port = Number(process.env.PORT ?? "8080");
const hostname = process.env.HOST ?? "0.0.0.0";

function relativePath(pathname: string): string | null {
	let decoded: string;
	try {
		decoded = decodeURIComponent(pathname);
	} catch {
		return null;
	}
	if (decoded.includes("\0") || decoded.split("/").includes("..")) return null;
	return decoded.replace(/^\/+/, "");
}

async function fileResponse(path: string): Promise<Response | null> {
	const file = Bun.file(path);
	if (!(await file.exists())) return null;
	if (!(await file.stat()).isFile()) return null;
	return new Response(file);
}

Bun.serve({
	hostname,
	port,
	async fetch(req) {
		const relative = relativePath(new URL(req.url).pathname);
		if (relative === null) return new Response("bad path", { status: 400 });

		if (relative !== "") {
			const exact = await fileResponse(`${root}/${relative}`);
			if (exact) return exact;
			const nested = await fileResponse(`${root}/${relative}/index.html`);
			if (nested) return nested;
		}

		const index = await fileResponse(`${root}/index.html`);
		if (index) return index;
		return new Response("client build missing", { status: 503 });
	},
});

console.log(`conduit-web listening on ${hostname}:${port}`);
