import { useEffect, useState } from "react";
import { Download, FileText, ImageOff } from "lucide-react";
import { describeError, formatBytes, type JsonObject } from "../core";
import { useClient } from "./hooks";

const MAX_W = 320;
const MAX_H = 240;

function fit(w?: unknown, h?: unknown): { width: number; height: number } {
  const width = typeof w === "number" && w > 0 ? w : MAX_W;
  const height = typeof h === "number" && h > 0 ? h : MAX_H;
  const scale = Math.min(1, MAX_W / width, MAX_H / height);
  return { width: Math.round(width * scale), height: Math.round(height * scale) };
}

/** Resolve an mxc:// URI to an object URL through the authenticated media API. */
function useMediaUrl(mxc: string | undefined, thumbnail?: { width: number; height: number }) {
  const client = useClient();
  const [state, setState] = useState<{ url?: string; error?: string }>({});
  const tw = thumbnail?.width;
  const th = thumbnail?.height;
  useEffect(() => {
    if (!mxc) return;
    let cancelled = false;
    setState({});
    client
      .mediaUrl(mxc, tw && th ? { width: tw, height: th } : undefined)
      .then((url) => !cancelled && setState({ url }))
      .catch((e) => !cancelled && setState({ error: describeError(e) }));
    return () => {
      cancelled = true;
    };
  }, [client, mxc, tw, th]);
  return state;
}

/** Inline image preview (thumbnail) that opens the full image. */
export function ImageMessage({ content, localUrl }: { content: JsonObject; localUrl?: string }) {
  const client = useClient();
  const info = (content.info ?? {}) as JsonObject;
  const size = fit(info.w, info.h);
  const mxc = typeof content.url === "string" ? content.url : undefined;
  const thumbSize = { width: Math.min(640, size.width * 2), height: Math.min(480, size.height * 2) };
  const { url, error } = useMediaUrl(localUrl ? undefined : mxc, thumbSize);
  const src = localUrl ?? url;
  const alt = typeof content.body === "string" ? content.body : "Image";
  if (error) {
    return (
      <p className="media-error" role="status" data-testid="media-error">
        <ImageOff size={16} aria-hidden="true" /> Couldn't load the image. {error}
      </p>
    );
  }
  return (
    <button
      type="button"
      className="media-image"
      style={{ width: size.width, height: size.height }}
      aria-label={`Open image ${alt}`}
      data-testid="media-image"
      onClick={async () => {
        if (!mxc) return;
        const full = await client.mediaUrl(mxc).catch(() => undefined);
        if (full) window.open(full, "_blank", "noopener");
      }}
    >
      {src ? <img src={src} alt={alt} width={size.width} height={size.height} data-testid="media-image-img" /> : <span className="media-skeleton" aria-label="Loading image" role="img" />}
    </button>
  );
}

/** A file card with name, size and a download action. */
export function FileMessage({ content }: { content: JsonObject }) {
  const client = useClient();
  const info = (content.info ?? {}) as JsonObject;
  const name = (typeof content.filename === "string" && content.filename) || (typeof content.body === "string" ? content.body : "file");
  const mxc = typeof content.url === "string" ? content.url : undefined;
  const [error, setError] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  return (
    <div className="file-card" data-testid="file-card">
      <FileText size={20} aria-hidden="true" />
      <span className="file-meta">
        <span className="file-name">{name}</span>
        <span className="file-size">{formatBytes(typeof info.size === "number" ? info.size : NaN)}</span>
      </span>
      {mxc && (
        <button
          type="button"
          className="icon-button"
          aria-label={`Download ${name}`}
          disabled={busy}
          data-testid="file-download"
          onClick={async () => {
            setBusy(true);
            setError(undefined);
            try {
              const url = await client.mediaUrl(mxc);
              const a = document.createElement("a");
              a.href = url;
              a.download = name;
              a.click();
            } catch (e) {
              setError(describeError(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          <Download size={18} aria-hidden="true" />
        </button>
      )}
      {error && (
        <span className="field-error" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

/** Read an image file's pixel size for the m.image info block. */
export function imageSize(file: File): Promise<{ w?: number; h?: number }> {
  if (!file.type.startsWith("image/") || typeof createImageBitmap !== "function") return Promise.resolve({});
  return createImageBitmap(file)
    .then((bitmap) => {
      const size = { w: bitmap.width, h: bitmap.height };
      bitmap.close();
      return size;
    })
    .catch(() => ({}));
}
