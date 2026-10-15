import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, openSync, closeSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

/** One real binary and fresh PG database per invocation, shared by the engines. */
export default async function setup() {
	const admin = process.env.DATABASE_URL ?? 'postgresql://postgres@localhost/postgres';
	const name = `conduit_svelte_${crypto.randomUUID().replaceAll('-', '')}`;
	const database = new URL(admin);
	database.pathname = `/${name}`;
	const files = resolve(web, 'test-results/server');
	mkdirSync(files, { recursive: true });
	const ready = resolve(files, 'ready.json');
	rmSync(ready, { force: true });
	const logs = resolve(files, 'server.log');
	let server: ChildProcess | undefined;
	let created = false;
	const awake = process.platform === 'darwin'
		? spawn('/usr/bin/caffeinate', ['-i', '-w', String(process.pid)], { stdio: 'ignore' }) : undefined;
	awake?.unref();
	function sql(statement: string) {
		execFileSync('psql', ['--no-psqlrc', admin, '-v', 'ON_ERROR_STOP=1', '-c', statement], {
			stdio: 'pipe', timeout: 15_000
		});
	}
	async function cleanup() {
		try {
			if (server?.pid && server.exitCode === null && server.signalCode === null) {
				const stopped = new Promise<void>(resolve => server!.once('exit', () => resolve()));
				server.kill('SIGTERM');
				const force = setTimeout(() => server!.kill('SIGKILL'), 5_000);
				try { await stopped; } finally { clearTimeout(force); }
			}
			if (created) sql(`DROP DATABASE ${name} WITH (FORCE)`);
		} finally { awake?.kill(); }
	}
	try {
		// An explicit binary supports local reuse; CI always builds locked sources.
		const target = resolve(web, '.cache/cargo');
		const binary = process.env.CONDUIT_SERVER_BIN
			? resolve(process.env.CONDUIT_SERVER_BIN) : resolve(target, 'debug/conduit-server');
		if (!process.env.CONDUIT_SERVER_BIN) {
			execFileSync('cargo', ['build', '--locked', '-p', 'conduit-server', '--target-dir', target], {
				cwd: resolve(web, '..'), stdio: 'inherit',
				env: { ...process.env, SQLX_OFFLINE: 'true', CARGO_NET_GIT_FETCH_WITH_CLI: 'true' }
			});
		}
		if (!existsSync(binary)) throw new Error(`Missing conduit-server binary: ${binary}`);
		sql(`CREATE DATABASE ${name}`);
		created = true;
		const log = openSync(logs, 'w');
		try {
			server = spawn(binary, [], {
				cwd: files, stdio: ['ignore', log, log],
				env: {
					...process.env,
					DATABASE_URL: database.toString(),
					CONDUIT_SERVER_NAME: 'svelte.test',
					CONDUIT_LISTEN_ADDR: '127.0.0.1:0',
					CONDUIT_READY_FILE: ready,
					CONDUIT_MEDIA_ROOT: resolve(files, 'media'),
					CONDUIT_AS_REGISTRATIONS_DIR: resolve(files, 'app-services'),
					CONDUIT_ALLOW_REGISTRATION: 'true',
					CONDUIT_REGISTRATION_TOKENS: '',
					CONDUIT_OIDC_ISSUER: 'off',
					CONDUIT_FEDERATION: '0',
					CONDUIT_REMOTE_KEYS_OVERRIDE: '',
					RUST_LOG: 'info'
				}
			});
		} finally { closeSync(log); }
		let spawnError: Error | undefined;
		server.on('error', error => { spawnError = error; });
		const deadline = Date.now() + 45_000;
		while (Date.now() < deadline) {
			if (spawnError) throw spawnError;
			if (server.exitCode !== null || server.signalCode !== null) {
				throw new Error(`conduit-server exited: ${readFileSync(logs, 'utf8')}`);
			}
			if (existsSync(ready)) {
				let address: string | undefined;
				try { address = JSON.parse(readFileSync(ready, 'utf8')).address; } catch { /* atomic readiness still pending */ }
				if (address) {
					const hs = `http://${address}`;
					const health = await fetch(`${hs}/health`, { signal: AbortSignal.timeout(2_000) }).catch(() => null);
					if (health?.ok && await health.text() === 'ok') {
						process.env.CONDUIT_TEST_HS = hs;
						return cleanup;
					}
				}
			}
			await new Promise(resolve => setTimeout(resolve, 50));
		}
		throw new Error(`conduit-server startup timed out: ${readFileSync(logs, 'utf8')}`);
	} catch (error) {
		await cleanup();
		throw error;
	}
}
