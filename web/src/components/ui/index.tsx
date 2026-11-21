import type { ButtonHTMLAttributes, ReactNode } from "react";

/** Shared primitives. Every button, field, panel and switcher in the app comes from here so the
    look changes in one place. Colours come from tokens only. */

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const VARIANT: Record<Variant, string> = {
  primary:
    "bg-accent text-on-accent shadow-[inset_0_1px_0_var(--btn-highlight),0_1px_2px_var(--btn-shadow)] hover:brightness-110 disabled:bg-panel2 disabled:text-muted disabled:shadow-[inset_0_0_0_1px_var(--border)]",
  secondary: "border border-line-strong bg-panel text-ink hover:border-accent hover:bg-panel2 disabled:opacity-50",
  ghost: "text-muted hover:bg-panel2 hover:text-ink disabled:opacity-50",
  danger: "border border-line-strong text-malicious hover:border-malicious disabled:opacity-50",
};
const SIZE: Record<Size, string> = {
  sm: "h-7 rounded-md px-2.5 text-xs",
  md: "h-9 rounded-lg px-4 text-sm",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export function Button({ variant = "secondary", size = "md", className = "", type = "button", ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={`inline-flex shrink-0 items-center justify-center gap-1.5 font-medium transition active:translate-y-px disabled:cursor-not-allowed ${SIZE[size]} ${VARIANT[variant]} ${className}`}
      {...rest}
    />
  );
}

/** Class string for text fields (input, textarea, select). */
export const FIELD =
  "w-full rounded-md border border-line-strong bg-bg px-3 py-1.5 text-sm outline-none transition-colors placeholder:text-muted focus:border-accent focus:ring-2 focus:ring-accent/30";

/** A titled surface. `flush` drops the body padding for tables and lists. */
export function Panel({
  title,
  label,
  action,
  flush = false,
  className = "",
  children,
}: {
  title: ReactNode;
  label: string;
  action?: ReactNode;
  flush?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section aria-label={label} className={`rounded-lg border border-line bg-panel ${className}`}>
      <header className="flex min-h-11 items-center gap-3 border-b border-line px-4 py-2">
        <h2 className="mr-auto text-sm font-semibold">{title}</h2>
        {action}
      </header>
      <div className={flush ? "" : "p-4"}>{children}</div>
    </section>
  );
}

/** Small section heading used inside the side column. */
export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <h2 className="flex items-baseline justify-between px-4 pb-1.5 pt-4 text-sm font-semibold">
      <span>{children}</span>
      {right && <span className="mono text-xs font-normal text-muted">{right}</span>}
    </h2>
  );
}

/** Segmented switcher. With `tabs` it renders a tablist (map, graph, raw); otherwise it is a
    set of pressed-state buttons used as the view navigation. */
export function Segmented<T extends string>({
  items,
  value,
  onChange,
  label,
  role,
  className = "",
}: {
  items: { id: T; label: string; hint?: string }[];
  value: T;
  onChange: (id: T) => void;
  label: string;
  role: "tab" | "nav";
  className?: string;
}) {
  const buttons = items.map((it) => {
    const on = value === it.id;
    return (
      <button
        key={it.id}
        type="button"
        role={role === "tab" ? "tab" : undefined}
        aria-selected={role === "tab" ? on : undefined}
        aria-current={role === "nav" && on ? "page" : undefined}
        onClick={() => onChange(it.id)}
        className={`flex h-7 items-center gap-1.5 rounded-md px-3 text-sm transition-colors ${on ? "bg-panel2 font-medium text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]" : "text-muted hover:text-ink"}`}
      >
        {it.label}
        {it.hint && <span className="mono text-[10px] text-muted">{it.hint}</span>}
      </button>
    );
  });
  const box = `flex gap-0.5 rounded-lg border border-line bg-bg p-0.5 ${className}`;
  return role === "tab" ? (
    <div role="tablist" aria-label={label} className={box}>
      {buttons}
    </div>
  ) : (
    <nav aria-label={label} className={box}>
      {buttons}
    </nav>
  );
}

/** Inline status line under a form: success, failure or a hint. */
export function Note({ tone = "muted", children }: { tone?: "muted" | "error"; children: ReactNode }) {
  if (!children) return null;
  return (
    <p role={tone === "error" ? "alert" : "status"} aria-live="polite" className={`text-xs ${tone === "error" ? "text-malicious" : "text-muted"}`}>
      {children}
    </p>
  );
}

/** Small tag for IOC types, cached flags and similar. */
export function Chip({ children, tone = "plain" }: { children: ReactNode; tone?: "plain" | "accent" }) {
  return (
    <span className={`mono inline-flex items-center rounded border px-1.5 text-[11px] leading-5 ${tone === "accent" ? "border-accent text-accent-text" : "border-line text-muted"}`}>
      {children}
    </span>
  );
}
