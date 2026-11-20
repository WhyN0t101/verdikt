import { forwardRef } from "react";

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
      className="flex min-w-0 flex-1 items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (value.trim() && !pending) onSubmit();
      }}
    >
      <label htmlFor="ioc" className="sr-only">
        IP, domain, URL or hash
      </label>
      <div className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-line-strong bg-panel px-3 focus-within:border-accent">
        <kbd className="label hidden shrink-0 rounded border border-line px-1 py-0.5 sm:block">Ctrl K</kbd>
        <input
          id="ioc"
          ref={ref}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Paste an IP, domain, URL or hash"
          spellCheck={false}
          autoComplete="off"
          className="mono h-10 min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted"
        />
      </div>
      <button
        type="submit"
        disabled={pending || !value.trim()}
        className="h-10 shrink-0 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
      >
        {pending ? "Checking…" : "Check"}
      </button>
    </form>
  );
});
