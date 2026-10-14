import type { HTMLAttributes } from "react";

interface FieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  error?: string;
  type?: string;
  autoComplete?: string;
  autoCapitalize?: string;
  spellCheck?: boolean;
  inputMode?: HTMLAttributes<HTMLInputElement>["inputMode"];
  placeholder?: string;
  testId?: string;
  multiline?: boolean;
  required?: boolean;
  autoFocus?: boolean;
}

/** Labelled input with hint and inline error wired up for assistive tech. */
export function Field(props: FieldProps) {
  const hintId = props.hint ? `${props.id}-hint` : undefined;
  const errorId = props.error ? `${props.id}-error` : undefined;
  const describedBy = [errorId, hintId].filter(Boolean).join(" ") || undefined;
  const common = {
    id: props.id,
    value: props.value,
    "aria-invalid": props.error ? true : undefined,
    "aria-describedby": describedBy,
    "data-testid": props.testId,
    placeholder: props.placeholder,
    required: props.required,
    autoFocus: props.autoFocus,
  };
  return (
    <div className={`field${props.error ? " field-invalid" : ""}`}>
      <label htmlFor={props.id} className="field-label">
        {props.label}
      </label>
      {props.multiline ? (
        <textarea {...common} rows={3} className="input" onChange={(e) => props.onChange(e.target.value)} />
      ) : (
        <input
          {...common}
          className="input"
          type={props.type ?? "text"}
          autoComplete={props.autoComplete}
          autoCapitalize={props.autoCapitalize}
          spellCheck={props.spellCheck}
          inputMode={props.inputMode}
          onChange={(e) => props.onChange(e.target.value)}
        />
      )}
      {props.error && (
        <p id={errorId} className="field-error" data-testid={props.testId ? `${props.testId}-error` : undefined}>
          {props.error}
        </p>
      )}
      {props.hint && (
        <p id={hintId} className="field-hint">
          {props.hint}
        </p>
      )}
    </div>
  );
}
