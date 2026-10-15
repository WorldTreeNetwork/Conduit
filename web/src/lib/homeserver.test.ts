/// <reference types="bun" />
import { describe, expect, test } from 'bun:test';
import { DEFAULT_HOMESERVER, homeserverProblem, resolveHomeserver } from './homeserver.js';

describe('resolveHomeserver', () => {
	test('?hs= wins and pins', () => {
		expect(resolveHomeserver('?hs=https://matrix.example', 'http://env:8008')).toEqual({
			url: 'https://matrix.example',
			pinned: true
		});
	});

	test('env var is next and does not pin', () => {
		expect(resolveHomeserver('', 'http://env:8008')).toEqual({ url: 'http://env:8008', pinned: false });
	});

	test('falls back to localhost', () => {
		expect(resolveHomeserver('', undefined)).toEqual({ url: DEFAULT_HOMESERVER, pinned: false });
		expect(DEFAULT_HOMESERVER).toBe('http://localhost:8008');
	});

	test('an empty ?hs= does not pin', () => {
		expect(resolveHomeserver('?hs=', undefined).pinned).toBe(false);
	});
});

describe('homeserverProblem', () => {
	test('empty, bad scheme, and garbage are reported', () => {
		expect(homeserverProblem('')).not.toBeNull();
		expect(homeserverProblem('ftp://x')).not.toBeNull();
		expect(homeserverProblem('localhost')).not.toBeNull();
		expect(homeserverProblem('http://localhost:8008')).toBeNull();
	});
});
