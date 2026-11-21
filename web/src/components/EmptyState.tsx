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
      <div className="hud pointer-events-auto grid max-w-3xl place-items-center gap-6 px-6 py-8">
        <div
          aria-hidden="true"
          className="h-16 w-16 rounded-full border border-line-strong"
          style={{ background: "repeating-linear-gradient(135deg, var(--violet-600) 0 2px, transparent 2px 6px)" }}
        />
        <div className="text-center">
          <h2 className="text-lg font-semibold">Check an indicator</h2>
          <p className="mt-1 max-w-md text-muted">Paste an IP, domain, URL or file hash. Defanged input like hxxp://evil[.]com works too.</p>
        </div>
        <ol className="grid w-full gap-3 sm:grid-cols-4">
          {STEPS.map(([n, name, text]) => (
            <li key={n} className="rounded border border-line-strong p-3">
              <span className="label text-accent-text">{n}</span>
              <div className="font-medium">{name}</div>
              <p className="mt-1 text-xs text-muted">{text}</p>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
