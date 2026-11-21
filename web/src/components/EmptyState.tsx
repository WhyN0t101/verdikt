const STEPS = [
  ["01", "Detect", "Refang, classify, reject internal targets"],
  ["02", "Query", "Threat-intel sources answer in parallel"],
  ["03", "Enrich", "Locate IPs, link related indicators"],
  ["04", "Verdict", "Rules decide: malicious, suspicious, safe or unknown"],
] as const;

/** Sits over the bare world map before the first check. */
export function EmptyState() {
  return (
    <div className="pointer-events-none absolute inset-0 z-10 grid place-items-center overflow-y-auto p-6">
      <div className="hud pointer-events-auto grid max-w-3xl place-items-center gap-7 px-8 py-9">
        <div aria-hidden="true" className="sphere" />
        <div className="text-center">
          <h2 className="text-2xl font-semibold tracking-tight">Check an indicator</h2>
          <p className="mt-2 max-w-md text-muted">Paste an IP, domain, URL or file hash. Defanged input like hxxp://evil[.]com works too.</p>
        </div>
        <ol className="grid w-full gap-3 sm:grid-cols-4">
          {STEPS.map(([n, name, text], i) => (
            <li
              key={n}
              className={`relative rounded-md border border-line-strong p-3 ${i < STEPS.length - 1 ? "sm:after:absolute sm:after:left-full sm:after:top-5 sm:after:h-px sm:after:w-3 sm:after:bg-[var(--violet-300)] sm:after:content-['']" : ""}`}
            >
              <span className="mono inline-block rounded-sm border border-accent px-1 text-[11px] leading-4 text-accent-text">{n}</span>
              <div className="mt-1.5 font-medium">{name}</div>
              <p className="mt-1 text-xs text-muted">{text}</p>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
