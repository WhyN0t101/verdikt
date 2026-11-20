# verdikt — Design Notes

Two references, kept in `docs/design/`:

- `ref-palette.webp`: **colours and texture.** Use this palette.
- `ref-layout.webp`: **layout and density idea.** Borrow the structure, not the colours.

Hex values below are estimated from the images. Tune them with the `frontend-design` skill and check contrast (≥ 4.5:1 for text) before locking them in `web/src/styles/tokens.css`.

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
- **Type:** geometric sans for UI and wordmark (Geist or Inter); mono for IOCs, labels, logs, numbers (Geist Mono or JetBrains Mono). Labels: uppercase, 11–12 px, letter-spacing ~0.08em.
- **Density:** compact like the layout reference; hairline dividers, no heavy cards or shadows.
- **Motion:** pixel-dissolve on results, reticle pulse on the active IOC, streaming log lines. All disabled under `prefers-reduced-motion`.

---

## 4. Map decision

The **dot-matrix world map** fits both references and removes the map-tile privacy leak entirely:

- Land is a precomputed grid of dots (from Natural Earth land polygons, built once into a small static JSON shipped with the app).
- Rendered with canvas/SVG or MapLibre with no remote tiles.
- No network requests for the map, so the country-zoom cap in `PLAN.md` is no longer needed for privacy.
- Markers: glowing dots in the level colour; arcs as thin violet leader lines with numbered callout boxes (palette reference motif).

This replaces the OpenFreeMap basemap in `PLAN.md` once confirmed during M6.

---

## 5. Open points for the `frontend-design` pass

- Final hex values and contrast check for both modes.
- Font choice (Geist vs Inter) and licensing.
- Whether the 3D point-cloud look (layout reference) is worth it for the globe, or a flat dot-matrix map is enough.
- Empty state: gradient sphere + `01–04` pipeline boxes.
