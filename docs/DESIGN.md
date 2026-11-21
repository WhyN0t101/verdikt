# verdikt — Design Notes

Two references, kept locally in `docs/design/` (git-ignored, not in the repo):

- `ref-palette.webp`: **colours and texture.** Use this palette.
- `ref-layout.webp`: **layout and density idea.** Borrow the structure, not the colours.

`web/src/styles/tokens.css` is authoritative for colours. The hex values below are the estimates the palette started from; where the two differ, the file wins. Text contrast stays ≥ 4.5:1.

**Skills:** invoke `frontend-design` before any UI work (M5–M7). Invoke `dataviz` before building the map, graph, timeline or any chart.

---

## 1. Palette reference (`ref-palette.webp`)

What it shows: off-white field with fine dot noise, faint concentric circle grid and thin `+` crosshair marks; violet/lavender pixel-mosaic imagery dissolving into blocks; a glowing indigo-violet gradient sphere; numbered outlined step boxes `01`–`04` joined by thin leader lines; diagonal hatched stripe bars; a bold geometric wordmark in a rounded-square badge.

### Colours (estimated)

| Token | Hex | Use |
|---|---|---|
| `--violet-600` | `#4B2FF0` | Primary accent, sphere core, active states |
| `--violet-500` | `#6A4CF5` | Buttons, focus ring, selected node |
| `--violet-300` | `#A98BEF` | Secondary marks, hatched bars |
| `--lavender-200` | `#CDBDF2` | Pixel blocks, subtle fills |
| `--plum-900` | `#24172F` | Darkest tone in imagery; dark-mode base tint |
| `--paper` | `#F6F5F8` | Light-mode background |
| `--ink` | `#111014` | Light-mode text |
| `--grid` | `#D9D6E0` | Circle grid, crosshairs, hairlines (light) |

### Texture and motifs to reuse

- **Dot-noise background** (subtle SVG/CSS noise), not flat colour.
- **Concentric circle grid + `+` crosshairs** behind the map/graph viewport.
- **Pixel-mosaic dissolve:** loading and transition effect (results "resolving" block by block). Respect `prefers-reduced-motion`.
- **Numbered outlined boxes with leader lines:** the pipeline view (`01 Detect · 02 Query · 03 Enrich · 04 Verdict`) and callout labels on the map/graph.
- **Hatched diagonal stripe bars:** progress, quota usage, per-source score bars.
- **Glowing gradient sphere:** the globe / hero on the empty state.
- **Rounded-square badge** for the `verdikt` mark, bold geometric wordmark.

---

## 2. Layout reference (`ref-layout.webp`)

What it shows: dark "mission control" app. Top bar with breadcrumb (`Nexus Core / Sector 05 / Orchestration Layer`), latency readout, one accent CTA. Left icon rail + collapsible grouped list with coloured status dots and right-aligned mono tags. Centre viewport with a 3D dot/point-cloud terrain and a crosshair reticle. Right column: timestamped mono **Activity stream** with coloured left borders, then a key/value **Diagnostics** panel. Bottom: playback controls, timecode, stacked area chart with a scrubber and a value tooltip (`SYSTEM LOAD 51.08%`). Small uppercase mono labels with wide tracking everywhere.

### Mapping to verdikt

| Reference element | verdikt element |
|---|---|
| Top bar breadcrumb | `verdikt / check / <ioc>` |
| Latency readout | Last lookup duration + **quota readout** (`VT 412/500`) |
| Accent CTA (orange) | `Check` button — **violet, not orange** (see §3) |
| Left grouped list with dots + mono tags | **History**, grouped by level (Malicious / Suspicious / Unknown / Safe), dot = level, tag = `IP` `DOM` `URL` `SHA256` |
| Centre viewport + reticle | **Map / Graph** tabs. Reticle marks the current IOC |
| Point-cloud terrain | **Dot-matrix world map** (land drawn as dots). See §4 |
| Activity stream | **Live source log**: one line per source as it answers, `[14:03:15] VIRUSTOTAL  12/94 MALICIOUS`, left border = row level |
| Diagnostics key/value | **Verdict panel**: Target, Type, Level, Confidence (`4/6`), ASN, Country, Reasons |
| Bottom timeline + stacked area | **Source waterfall**: one lane per source showing request start/end, cache hits, retries. Scrubber tooltip = latency |
| Uppercase mono labels | All section labels and IOC values |

---

## 3. Combined direction

- **Dark mode = primary** (layout reference structure, palette reference colours): base `--plum-900`-tinted near-black, violet accents, hairline `--grid` borders at low opacity, dot-noise overlay.
- **Light mode = the palette reference itself:** `--paper` with dot noise, circle grid, ink text.
- **One accent colour: violet.** The layout reference's orange CTA is dropped, because orange/amber/red are reserved for verdict levels.
- **Verdict colours stay separate from the brand violet:**

  | Level | Colour (estimate) |
  |---|---|
  | MALICIOUS | `#FF4D5E` red |
  | SUSPICIOUS | `#FFB020` amber |
  | SAFE | `#2BD9A0` teal-green |
  | UNKNOWN | `#8A8794` grey |
  | INFO (rows only) | `--violet-300` |

  Level is always text + icon too, never colour alone.
- **Type:** Familjen Grotesk for UI and wordmark; Martian Mono for IOCs, labels, logs, numbers (both via `@fontsource-variable`, OFL).
- **Surfaces:** flat neutral black and white, no tinted panels or gradients; violet only as the accent. The one gradient is the globe on the empty state (`.sphere` in `web/src/styles/index.css`). Section headings are sentence case, semibold; the uppercase mono `.label` (11–12 px, letter-spacing ~0.08em) stays for small data tags such as the IOC type.
- **Shell:** one header holds the logo, the view switcher (Check, Overview, Batch, Cases), the command bar, readouts and the theme toggle. The switcher and the Map/Graph/Raw JSON tabs are the same `Segmented` component in `web/src/components/ui/index.tsx`.
- **Density:** compact like the layout reference; hairline dividers, no heavy cards or shadows.
- **Motion:** pixel-dissolve on results, reticle pulse on the active IOC, streaming log lines. All disabled under `prefers-reduced-motion`.

---

## 4. Map decision

The **dot-matrix world map** (shipped) fits both references and removes the map-tile privacy leak entirely:

- Land is a precomputed grid of dots (from Natural Earth land polygons, built once into a small static JSON shipped with the app).
- Rendered as one SVG path in `web/src/components/MapView.tsx`. There are no tiles and no zoom.
- The map makes no network request, so what you investigate is never revealed through map traffic.
- Markers: glowing dots in the level colour; arcs as thin violet leader lines with numbered callout boxes (palette reference motif).

---

## 5. Resolved design points

- Colours: `web/src/styles/tokens.css` is the source, with a light and a dark theme.
- Fonts: Familjen Grotesk for the UI and Martian Mono for IOCs, labels, logs and numbers.
- Map: a flat dot-matrix map, not a 3D point cloud.
- Empty state: gradient sphere and the `01–04` pipeline boxes joined by leader lines.
