// Boots an ephemeral conduit-server for the e2e run, with the same
// environment as conduit-server/tests/common/production.rs: a fresh
// PostgreSQL database, a loopback port chosen by the OS, readiness signalled
// through CONDUIT_READY_FILE, OIDC and federation off. Tears everything down
// (process, database, temp files) when the run ends.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
export const STATE_FILE = join(here, ".state", "server.json");
export const SERVER_NAME = "conduit.test";

function psql(adminUrl: string, sql: string): void {
  execFileSync("psql", ["--no-psqlrc", adminUrl, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], { stdio: "pipe" });
}

function locateServer(): string {
  const explicit = process.env.CONDUIT_SERVER_BIN;
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`CONDUIT_SERVER_BIN=${explicit} does not exist`);
    return explicit;
  }
  // Incremental: a no-op when the binary is current.
  execFileSync("cargo", ["build", "-p", "conduit-server"], {
    cwd: repoRoot,
    stdio: "inherit",
    env: { ...process.env, SQLX_OFFLINE: "true" },
  });
  const targetDir = process.env.CARGO_TARGET_DIR ?? join(repoRoot, "target");
  const bin = join(targetDir, "debug", "conduit-server");
  if (!existsSync(bin)) throw new Error(`conduit-server binary not found at ${bin}`);
  return bin;
}

async function waitForReady(child: ChildProcess, readyFile: string, logFile: string): Promise<string> {
  const deadline = Date.now() + 60_000;
  let exited: number | null = null;
  child.once("exit", (code) => (exited = code ?? -1));
  for (;;) {
    if (exited !== null) {
      throw new Error(`conduit-server exited (${exited}) before ready:\n${readFileSync(logFile, "utf8")}`);
    }
    if (existsSync(readyFile)) {
      try {
        const { address } = JSON.parse(readFileSync(readyFile, "utf8")) as { address?: string };
        if (address) {
          const base = `http://${address}`;
          const health = await fetch(`${base}/health`).catch(() => undefined);
          if (health?.ok && (await health.text()) === "ok") return base;
        }
      } catch {
        // Partially written; poll again.
      }
    }
    if (Date.now() > deadline) {
      throw new Error(`conduit-server did not become ready:\n${readFileSync(logFile, "utf8")}`);
    }
    // Polling an observable condition (the ready file), not a fixed wait.
    await new Promise((r) => setTimeout(r, 50));
  }
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  // Keep unattended macOS runs awake while Playwright lives. Watching this
  // PID also releases the assertion if setup fails or the runner is killed.
  const awake = process.platform === "darwin"
    ? spawn("/usr/bin/caffeinate", ["-i", "-w", String(process.pid)], { stdio: "ignore" })
    : undefined;
  if (awake) {
    await new Promise<void>((resolve, reject) => {
      awake.once("spawn", resolve);
      awake.once("error", reject);
    });
    awake.unref();
    console.log(`[e2e] idle-sleep guard pid=${awake.pid}`);
  }
  try {
    const teardown = await bootServer();
    return async () => {
      try { await teardown(); }
      finally { awake?.kill(); }
    };
  } catch (error) {
    awake?.kill();
    throw error;
  }
}

async function bootServer(): Promise<() => Promise<void>> {
  if (process.env.CONDUIT_E2E_HS) {
    // Pointed at an already-running homeserver: nothing to manage.
    return async () => {};
  }
  const bin = locateServer();
  const adminUrl = process.env.DATABASE_URL ?? "postgresql://postgres@localhost/postgres";
  const dbName = `conduit_client_e2e_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  const dbUrl = new URL(adminUrl);
  dbUrl.pathname = `/${dbName}`;
  psql(adminUrl, `CREATE DATABASE ${dbName}`);

  const files = mkdtempSync(join(tmpdir(), "conduit-client-e2e-"));
  const readyFile = join(files, "ready.json");
  const logFile = join(files, "server.log");
  const log = openSync(logFile, "a");
  const child = spawn(bin, [], {
    cwd: files,
    stdio: ["ignore", log, log],
    env: {
      ...process.env,
      DATABASE_URL: dbUrl.toString(),
      CONDUIT_SERVER_NAME: SERVER_NAME,
      CONDUIT_LISTEN_ADDR: "127.0.0.1:0",
      CONDUIT_READY_FILE: readyFile,
      CONDUIT_MEDIA_ROOT: join(files, "media"),
      CONDUIT_OIDC_ISSUER: "off",
      CONDUIT_FEDERATION: "0",
      CONDUIT_AS_REGISTRATIONS_DIR: join(files, "app-services"),
      RUST_LOG: process.env.RUST_LOG ?? "info",
    },
  });

  let baseUrl: string;
  try {
    baseUrl = await waitForReady(child, readyFile, logFile);
  } catch (error) {
    child.kill("SIGKILL");
    psql(adminUrl, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    throw error;
  }

  process.env.CONDUIT_E2E_HS = baseUrl;
  process.env.CONDUIT_E2E_SERVER_NAME = SERVER_NAME;
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify({ baseUrl, serverName: SERVER_NAME, dbName, logFile }, null, 2));
  console.log(`[e2e] conduit-server ${baseUrl} db=${dbName} log=${logFile}`);

  return async () => {
    const exited = new Promise<void>((resolve) => {
      if (child.exitCode !== null) resolve();
      else child.once("exit", () => resolve());
    });
    child.kill("SIGTERM");
    const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
    await exited;
    clearTimeout(timer);
    psql(adminUrl, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    if (process.env.CONDUIT_E2E_KEEP_LOGS) {
      console.log(`[e2e] server log kept at ${logFile}`);
    } else {
      rmSync(files, { recursive: true, force: true });
    }
    rmSync(STATE_FILE, { force: true });
  };
}
