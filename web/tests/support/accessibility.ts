import { expect, type Page, type TestInfo } from '@playwright/test';
import { createRequire } from 'node:module';
import type { AxeResults } from 'axe-core';

const require = createRequire(import.meta.url);

export async function assertAccessibleShell(page: Page, info: TestInfo) {
	await expect(page.getByTestId('sync-status')).toHaveAttribute('data-state', 'live');
	await page.evaluate(() => document.fonts.ready);
	await page.addScriptTag({ path: require.resolve('axe-core/axe.min.js') });
	const results = await page.evaluate(async () => {
		return (window as unknown as { axe: { run(): Promise<AxeResults> } }).axe.run();
	});
	await info.attach('signed-in-shell-axe', {
		body: JSON.stringify(results, null, 2), contentType: 'application/json'
	});
	expect(results.violations.filter(v => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}
