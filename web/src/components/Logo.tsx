/** Three broken rings around a two-facet V; mirrors docs/logo.svg and the tab icon. */
export function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <svg aria-hidden="true" viewBox="0 0 64 64" className="h-9 w-9">
        <g fill="none" pathLength="100">
          <circle cx="32" cy="32" r="28.5" stroke="var(--violet-500)" strokeWidth="2.6" pathLength="100" strokeDasharray="78 22" transform="rotate(-70 32 32)" />
          <circle cx="32" cy="32" r="24.5" stroke="currentColor" strokeWidth="2" pathLength="100" strokeDasharray="60 10 22 8" transform="rotate(110 32 32)" />
          <circle cx="32" cy="32" r="20.5" stroke="currentColor" strokeWidth="1.3" pathLength="100" strokeDasharray="92 8" transform="rotate(30 32 32)" />
        </g>
        <path d="M18.5 21h7.4L32 35.5V48z" fill="currentColor" />
        <path d="M45.5 21h-7.4L32 35.5V48z" fill="currentColor" fillOpacity=".62" />
      </svg>
      <span className="text-xl font-bold leading-none tracking-tight">verdikt</span>
      <span aria-hidden="true" className="mono hidden h-4 border-l border-line-strong pl-2.5 text-[10px] leading-4 text-muted md:block">
        IOC triage
      </span>
    </span>
  );
}
