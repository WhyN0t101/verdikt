import { forwardRef } from "react";
import { Button } from "./ui";

interface Props {
  value: string;
  pending: boolean;
  onChange: (v: string) => void;
  onSubmit: () => void;
}

export const CommandBar = forwardRef<HTMLInputElement, Props>(function CommandBar(
  { value, pending, onChange, onSubmit },
  ref,
) {
  return (
    <form
      className="order-last flex min-w-0 basis-full items-center gap-2 sm:order-none sm:basis-0 sm:flex-1"
      onSubmit={(e) => {
        e.preventDefault();
        if (value.trim() && !pending) onSubmit();
      }}
    >
      <label htmlFor="ioc" className="sr-only">
        IP, domain, URL or hash
      </label>
      <div className="flex h-11 min-w-0 flex-1 items-center gap-2.5 rounded-lg border border-line-strong bg-bg px-3.5 transition-colors focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/30">
        <svg aria-hidden="true" viewBox="0 0 20 20" className="h-4 w-4 shrink-0 text-muted" fill="none" stroke="currentColor" strokeWidth="1.8">
          <circle cx="8.5" cy="8.5" r="5.5" />
          <path d="M13 13l4 4" strokeLinecap="round" />
        </svg>
        <input
          id="ioc"
          ref={ref}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Paste an IP, domain, URL or hash"
          spellCheck={false}
          autoComplete="off"
          className="mono h-full min-w-0 flex-1 bg-transparent text-[13px] outline-none placeholder:text-muted"
        />
        <kbd className="mono hidden shrink-0 rounded-md border border-line-strong px-1.5 py-0.5 text-[10px] leading-none text-muted shadow-[0_1px_0_var(--border-strong)] sm:block">Ctrl K</kbd>
      </div>
      <Button type="submit" variant="primary" className="h-11 px-5 text-sm" disabled={pending || !value.trim()}>
        {pending ? "Checking…" : "Check"}
      </Button>
    </form>
  );
});
