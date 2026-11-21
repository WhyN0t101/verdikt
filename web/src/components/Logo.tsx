/** Reticle ring broken at the four compass points, with a solid verdict chevron locked inside. */
export function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <svg aria-hidden="true" viewBox="0 0 32 32" className="h-8 w-8">
        <circle cx="16" cy="16" r="13.5" fill="none" stroke="currentColor" strokeWidth="2" pathLength="100" strokeDasharray="19 6" transform="rotate(9 16 16)" />
        <path d="M9 11.5h4.4L16 17.6l2.6-6.1H23L16 25.5z" fill="var(--accent-text)" />
        <rect x="14.6" y="5.6" width="2.8" height="2.8" fill="var(--accent-text)" />
      </svg>
      <span className="text-xl font-bold leading-none tracking-tight">verdikt</span>
      <span aria-hidden="true" className="mono hidden h-4 border-l border-line-strong pl-2.5 text-[10px] leading-4 text-muted md:block">
        IOC triage
      </span>
    </span>
  );
}
