// The window.__conduitClient automation hook, typed for page.evaluate().
import type { ConduitTestHook } from "../src/testHook";

declare global {
  interface Window {
    __conduitClient?: ConduitTestHook;
  }
}

export {};
