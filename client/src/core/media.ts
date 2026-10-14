// Content repository: uploads and authenticated (v1) downloads.
// https://spec.matrix.org/v1.19/client-server-api/#content-repository
import type { HttpClient } from "./http";
import { enc } from "./http";

export interface MxcParts {
  serverName: string;
  mediaId: string;
}

export function parseMxc(uri: unknown): MxcParts | undefined {
  if (typeof uri !== "string") return undefined;
  const match = /^mxc:\/\/([^/]+)\/([A-Za-z0-9_-]+)$/.exec(uri);
  return match ? { serverName: match[1]!, mediaId: match[2]! } : undefined;
}

export async function uploadMedia(http: HttpClient, data: Blob, filename: string, contentType: string): Promise<string> {
  const response = await http.request<{ content_uri?: string }>("POST", "/_matrix/media/v3/upload", {
    query: { filename },
    raw: { data, contentType: contentType || "application/octet-stream" },
    maxRetries: 1,
  });
  if (!response.content_uri || !parseMxc(response.content_uri)) {
    throw new Error("The server did not return a content URI for the upload.");
  }
  return response.content_uri;
}

export function downloadPath(parts: MxcParts): string {
  return `/_matrix/client/v1/media/download/${enc(parts.serverName)}/${enc(parts.mediaId)}`;
}

export function thumbnailPath(parts: MxcParts): string {
  return `/_matrix/client/v1/media/thumbnail/${enc(parts.serverName)}/${enc(parts.mediaId)}`;
}

/** msgtype for an attachment from its MIME type. */
export function msgtypeFor(mimetype: string): "m.image" | "m.video" | "m.audio" | "m.file" {
  if (mimetype.startsWith("image/")) return "m.image";
  if (mimetype.startsWith("video/")) return "m.video";
  if (mimetype.startsWith("audio/")) return "m.audio";
  return "m.file";
}

export function formatBytes(size: number): string {
  if (!Number.isFinite(size) || size < 0) return "";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}
