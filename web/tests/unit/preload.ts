import { describe, expect, it, mock } from 'bun:test';

// Run the framework-free core's existing assertions under Bun.
// The test files still import vitest; this module supplies that export.
mock.module('vitest', () => ({ describe, expect, it }));

// Bun 1.3.14 appends charset=utf-8 to a File's explicitly supplied text MIME
// type. Browsers preserve that type; use the browser behavior for core tests.
class BrowserFile extends File {
	private readonly suppliedType: string;
	constructor(bits: BlobPart[], name: string, options?: FilePropertyBag) {
		super(bits, name, options);
		this.suppliedType = options?.type?.toLowerCase() ?? '';
	}
	override get type() { return this.suppliedType; }
}
globalThis.File = BrowserFile;
