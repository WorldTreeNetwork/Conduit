import { describe, expect, test } from 'bun:test';
import { legacyRedirect, proxyToHomeserver } from './public-host.js';

describe('legacyRedirect', () => {
	test('sends the old web host to the public origin and keeps the path', () => {
		expect(legacyRedirect('conduit-web.vm.worldtree.network', '/#/room/1')).toBe(
			'https://conduit.worldtree.network/#/room/1'
		);
		expect(legacyRedirect('Conduit-Web.vm.worldtree.network:443', '/')).toBe(
			'https://conduit.worldtree.network/'
		);
	});

	test('leaves the public host and the homeserver host alone', () => {
		expect(legacyRedirect('conduit.worldtree.network', '/')).toBeNull();
		expect(legacyRedirect('conduit.vm.worldtree.network', '/_matrix/client/versions')).toBeNull();
	});
});

describe('proxyToHomeserver', () => {
	test('covers the client API and Matrix discovery', () => {
		expect(proxyToHomeserver('/_matrix/client/v3/sync')).toBe(true);
		expect(proxyToHomeserver('/.well-known/matrix/client')).toBe(true);
		expect(proxyToHomeserver('/.well-known/matrix')).toBe(false);
		expect(proxyToHomeserver('/')).toBe(false);
	});
});
