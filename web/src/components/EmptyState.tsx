const STEPS = [
  ["01", "Detect", "Refang, classify, reject internal targets"],
  ["02", "Query", "Threat-intel sources answer in parallel"],
  ["03", "Enrich", "Locate IPs, link related indicators"],
  ["04", "Verdict", "Rules decide: malicious, suspicious, safe or unknown"],
] as const;

export function EmptyState() {
  return (
    <div className="grid place-items-center gap-8 rounded-md border border-line bg-panel px-4 py-12">
      <div
        aria-hidden="true"
        className="h-32 w-32 rounded-full"
        style={{
          background: "radial-gradient(circle at 35% 30%, var(--violet-300), var(--violet-600) 55%, var(--plum-900) 100%)",
          boxShadow: "0 0 60px 8px color-mix(in srgb, var(--violet-500) 35%, transparent)",
        }}
      />
      <div className="text-center">
        <h2 className="text-lg font-semibold">Check an indicator</h2>
        <p className="mt-1 max-w-md text-muted">Paste an IP, domain, URL or file hash. Defanged input like hxxp://evil[.]com works too.</p>
      </div>
      <ol className="grid w-full max-w-3xl gap-3 sm:grid-cols-4">
        {STEPS.map(([n, name, text]) => (
          <li key={n} className="relative rounded border border-line-strong p-3">
            <span className="label text-accent-text">{n}</span>
            <div className="font-medium">{name}</div>
            <p className="mt-1 text-xs text-muted">{text}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}
