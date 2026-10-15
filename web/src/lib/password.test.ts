/// <reference types="bun" />
import { describe, expect, test } from 'bun:test';
import { passwordLoginEnabled } from './password.js';

describe('passwordLoginEnabled', () => {
	test('is off unless the build explicitly turns it on', () => {
		for (const off of [undefined, null, '', '0', 'false', 'off', 'no', 'password']) {
			expect(passwordLoginEnabled(off)).toBe(false);
		}
		for (const on of ['1', 'true', 'TRUE', 'on', 'yes']) {
			expect(passwordLoginEnabled(on)).toBe(true);
		}
	});
});
