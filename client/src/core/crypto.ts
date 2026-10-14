// End-to-end encryption seam.
//
// Phase 3 plugs an OlmMachine from @matrix-org/matrix-sdk-crypto-wasm in
// behind this interface; the core never implements cryptography itself.
// The sync engine feeds every sync's to-device events, device-list changes
// and one-time-key counts into the backend before rooms are processed, the
// room model asks it to decrypt m.room.encrypted events, and the send queue
// asks it to encrypt content for encrypted rooms.
import type { JsonObject, MatrixEvent, SyncResponse } from "./types";

export interface CryptoBackend {
  readonly enabled: boolean;
  /** Called with each /sync response before room processing. */
  receiveSyncChanges(sync: SyncResponse): Promise<void>;
  /** Decrypt an m.room.encrypted event; return undefined if not possible yet. */
  decryptEvent(event: MatrixEvent): Promise<MatrixEvent | undefined>;
  /** Encrypt an outgoing room event (returns m.room.encrypted). */
  encryptRoomEvent(roomId: string, type: string, content: JsonObject): Promise<{ type: string; content: JsonObject }>;
  /** Flush pending outgoing key requests (keys/upload, keys/query, to-device). */
  processOutgoingRequests(): Promise<void>;
}

export class EncryptionUnavailableError extends Error {
  constructor() {
    super("This room is encrypted and this client cannot encrypt messages yet.");
    this.name = "EncryptionUnavailableError";
  }
}

/** Default backend: no E2EE. Encrypted rooms refuse sends with a clear error. */
export const noCrypto: CryptoBackend = {
  enabled: false,
  async receiveSyncChanges() {},
  async decryptEvent() {
    return undefined;
  },
  async encryptRoomEvent() {
    throw new EncryptionUnavailableError();
  },
  async processOutgoingRequests() {},
};
