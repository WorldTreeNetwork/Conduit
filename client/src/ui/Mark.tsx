/**
 * The Conduit mark: a carrier capsule in a tube section. Also used, scaled
 * down, as the per-message carrier status glyph (see CarrierMark).
 */
export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className="mark">
      <rect x="2" y="9" width="28" height="14" rx="7" fill="none" stroke="currentColor" strokeWidth="2" />
      <rect x="8" y="12.5" width="13" height="7" rx="3.5" fill="var(--color-brass)" />
      <path d="M2 16h3M27 16h3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export type CarrierState = "queued" | "sending" | "sent" | "delivered" | "failed";

const LABELS: Record<CarrierState, string> = {
  queued: "Waiting to send",
  sending: "Sending",
  sent: "Sent",
  delivered: "Delivered",
  failed: "Not sent",
};

/** Where a carrier is: hollow queued, filling in-tube, solid delivered, notched red jammed. */
export function CarrierMark({ state }: { state: CarrierState }) {
  return (
    <span className={`carrier carrier-${state}`} data-testid="carrier-mark" data-state={state} title={LABELS[state]}>
      <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true">
        <rect className="carrier-shell" x="1" y="1" width="16" height="8" rx="4" />
        <rect className="carrier-fill" x="1" y="1" width="16" height="8" rx="4" />
        {state === "failed" && <path className="carrier-notch" d="M9 0v10" />}
      </svg>
      <span className="visually-hidden">{LABELS[state]}</span>
    </span>
  );
}
