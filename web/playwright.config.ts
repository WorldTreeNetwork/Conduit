import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.WEB_PORT ?? 4173);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('WEB_PORT must be a TCP port.');
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
	testDir: './tests',
	testMatch: '*.spec.ts',
	globalSetup: './tests/support/server.ts',
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	workers: 1,
	retries: 0,
	timeout: 180_000,
	expect: { timeout: 15_000 },
	reporter: [['list'], ['html', { open: 'never' }]],
	use: {
		baseURL,
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure'
	},
	projects: [
		{ name: 'chromium', use: { ...devices['Desktop Chrome'] } },
		{ name: 'firefox', use: { ...devices['Desktop Firefox'] } },
		{ name: 'webkit', use: { ...devices['Desktop Safari'] } }
	],
	webServer: {
		command: `bun run build && bun run preview --host 127.0.0.1 --port ${port} --strictPort`,
		url: baseURL,
		reuseExistingServer: false,
		timeout: 120_000
	}
});
