// Data-agnostic layout components for the Startup-SBOM PDF report.
// Every argument that originates from scan, advisory or AI data is a plain
// value (string, number, bool, dictionary) rendered as text; nothing here
// evaluates data as markup, fetches packages or touches files.

#let c-ink = rgb("#111827")
#let c-mute = rgb("#6b7280")
#let c-rule = rgb("#e5e7eb")
#let c-fill = rgb("#f3f4f6")
#let c-soft = rgb("#f9fafb")
#let c-accent = rgb("#1d4ed8")
#let c-ok = rgb("#15803d")

#let tones = (
  critical: rgb("#7f1d1d"),
  high: rgb("#dc2626"),
  medium: rgb("#b45309"),
  low: rgb("#2563eb"),
  info: rgb("#6b7280"),
  "none": rgb("#9ca3af"),
  unknown: rgb("#9ca3af"),
  neutral: rgb("#6b7280"),
  base: rgb("#9ca3af"),
  up: rgb("#dc2626"),
  down: rgb("#15803d"),
  total: rgb("#111827"),
)
#let tone-color(t) = tones.at(t, default: c-mute)

// Invisible, queryable section marker (used by tests and tooling).
#let mark-section(name) = [#metadata(name) <sbom-section>]

// Monospace text that wraps (unlike inline raw) for ids, paths and versions.
#let mono(v, size: 8pt) = text(font: "DejaVu Sans Mono", size: size, v)

// A label/value pair for a two-column fact grid (spliced with `..`).
#let field(k, v) = (text(7.5pt, fill: c-mute, k), text(8.5pt, v))

#let pill(label, tone) = box(
  fill: tone-color(tone),
  radius: 2pt,
  inset: (x: 4pt, y: 2pt),
  baseline: 20%,
  text(6.5pt, fill: white, weight: "bold", tracking: 0.4pt, upper(label)),
)

#let chip(body, tone: none) = box(
  stroke: 0.5pt + (if tone == none { c-rule } else { tone-color(tone) }),
  fill: c-soft,
  radius: 2pt,
  inset: (x: 3.5pt, y: 2pt),
  baseline: 20%,
  text(7pt, fill: if tone == none { c-ink } else { tone-color(tone) }, body),
)

#let note-box(body, tone: "medium") = block(
  width: 100%,
  radius: 3pt,
  inset: 8pt,
  fill: tone-color(tone).lighten(93%),
  stroke: 0.6pt + tone-color(tone).lighten(40%),
  text(8pt, body),
)

#let kpi(k) = block(
  width: 100%,
  fill: c-fill,
  radius: 3pt,
  inset: 8pt,
  stroke: (left: 2pt + tone-color(k.tone), rest: 0.5pt + c-rule),
)[
  #set par(justify: false)
  #text(6.5pt, fill: c-mute, tracking: 0.6pt, upper(k.label)) \
  #text(16pt, weight: "bold", fill: c-ink, k.value) \
  #text(7pt, fill: c-mute, k.sub)
]

// Horizontal gauge: a 0..1 fraction on a soft track.
#let meter(frac, tone) = box(
  width: 100%,
  height: 7pt,
  fill: c-soft,
  radius: 3.5pt,
  place(
    left + horizon,
    box(width: 100% * frac, height: 100%, radius: 3.5pt, fill: tone-color(tone)),
  ),
)

// Horizontal bars: label | bar scaled by `frac` | count.
#let bar-chart(rows) = grid(
  columns: (24mm, 1fr, 10mm),
  row-gutter: 4.5pt,
  column-gutter: 6pt,
  align: (right + horizon, left + horizon, left + horizon),
  ..rows
    .map(r => (
      text(7.5pt, fill: c-mute, upper(r.label)),
      box(
        width: 100%,
        height: 9pt,
        fill: c-soft,
        radius: 1.5pt,
        place(
          left + horizon,
          box(width: 100% * r.frac, height: 100%, radius: 1.5pt, fill: tone-color(r.tone)),
        ),
      ),
      text(8pt, weight: "bold", str(r.count)),
    ))
    .flatten(),
)

// Reference to a report element: internal link when rendered, dashed red box
// when the id does not exist in the report (e.g. hallucinated AI evidence).
#let evref(e) = if e.at("anchor", default: none) != none {
  link(label(e.anchor), mono(e.id, size: 7.5pt))
} else if e.at("state", default: "known") == "unknown" {
  box(
    stroke: (paint: tones.high, dash: "dashed", thickness: 0.6pt),
    radius: 2pt,
    inset: (x: 2.5pt, y: 1.5pt),
    baseline: 20%,
    mono(e.id, size: 7.5pt) + text(6.5pt, fill: tones.high)[ — not in this report],
  )
} else {
  mono(e.id, size: 7.5pt)
}

#let ref-list(refs) = if refs.len() == 0 { text(fill: c-mute, "—") } else {
  refs.map(evref).join(", ")
}

// "Why this score" waterfall: each row carries pre-computed geometry
// (x0, w as 0..1 fractions of the track) plus a signed delta label.
#let waterfall(ch) = {
  set par(justify: false)
  grid(
    columns: (38mm, 1fr, 13mm),
    row-gutter: 3.5pt,
    column-gutter: 6pt,
    align: (right + horizon, left + horizon, right + horizon),
    ..ch
      .rows
      .map(r => (
        {
          text(7pt, fill: if r.tone == "total" { c-ink } else { c-mute }, r.label)
          if r.detail != "" { text(6.2pt, fill: c-mute, " (" + r.detail + ")") }
        },
        box(
          width: 100%,
          height: 8pt,
          stroke: (bottom: 0.3pt + c-rule),
          place(
            left + horizon,
            dx: 100% * r.x0,
            box(width: 100% * r.w, height: 100%, fill: tone-color(r.tone)),
          ),
        ),
        text(7pt, weight: if r.tone in ("total", "base") { "bold" } else { "regular" }, r.delta),
      ))
      .flatten(),
  )
}

// Top system-risk drivers: linked label | bar | contribution | share.
#let driver-chart(rows) = grid(
  columns: (48mm, 1fr, 12mm, 9mm),
  row-gutter: 4pt,
  column-gutter: 5pt,
  align: (right + horizon, left + horizon, right + horizon, right + horizon),
  ..rows
    .map(r => (
      {
        set par(justify: false)
        set text(7.5pt)
        if r.ref.at("anchor", default: none) != none { link(label(r.ref.anchor), r.label) } else { r.label }
        text(6.2pt, fill: c-mute, " · " + r.kind)
      },
      box(
        width: 100%,
        height: 8.5pt,
        fill: c-soft,
        radius: 1.5pt,
        place(
          left + horizon,
          box(width: 100% * r.frac, height: 100%, radius: 1.5pt, fill: c-accent),
        ),
      ),
      text(7.5pt, weight: "bold", r.value),
      text(7pt, fill: c-mute, r.share),
    ))
    .flatten(),
)

// ------------------------------------------------------------- attack chains
#let state-box(n) = box(
  inset: (x: 7pt, y: 5pt),
  radius: 3pt,
  fill: if n.goal { tones.critical } else if n.entry { white } else { rgb("#eef2ff") },
  stroke: if n.goal { none } else { 0.8pt + c-accent },
  text(
    7.5pt,
    weight: "bold",
    font: "DejaVu Sans Mono",
    fill: if n.goal { white } else { c-ink },
    n.label,
  ),
)

#let step-label(st) = {
  set par(justify: false)
  set text(6.5pt, fill: c-mute)
  st.title
  if st.technique != none [ · #st.technique.id]
  [ · p=#st.likelihood]
  if st.mitigated {
    linebreak()
    text(fill: c-ok, weight: "bold", "mitigated")
  }
}

#let h-arrow(st) = {
  let paint = if st.mitigated { c-ok } else { c-mute }
  let dash = if st.mitigated { "dashed" } else { "solid" }
  stack(
    dir: ttb,
    spacing: 2.5pt,
    align(center, step-label(st)),
    box(width: 100%, height: 6pt, {
      place(
        left + horizon,
        line(length: 100% - 5pt, stroke: (paint: paint, thickness: 1.1pt, dash: dash)),
      )
      place(right + top, polygon(fill: paint, (0pt, 0pt), (5pt, 3pt), (0pt, 6pt)))
    }),
  )
}

#let v-arrow(st) = {
  let paint = if st.mitigated { c-ok } else { c-mute }
  let dash = if st.mitigated { "dashed" } else { "solid" }
  grid(
    columns: (14pt, 1fr),
    column-gutter: 6pt,
    box(width: 100%, height: 18pt, {
      place(
        center + top,
        line(angle: 90deg, length: 13pt, stroke: (paint: paint, thickness: 1.1pt, dash: dash)),
      )
      place(center + bottom, polygon(fill: paint, (0pt, 0pt), (6pt, 0pt), (3pt, 4.5pt)))
    }),
    align(left + horizon, step-label(st)),
  )
}

// Privilege-state diagram: boxes joined by labelled arrows, drawn with native
// shapes only.  `row` layout for short chains, `column` for long ones.
#let chain-diagram(ch) = block(
  width: 100%,
  inset: 8pt,
  radius: 4pt,
  stroke: 0.5pt + c-rule,
  if ch.layout == "row" {
    let cols = ()
    let cells = ()
    for (i, n) in ch.nodes.enumerate() {
      cols.push(auto)
      cells.push(state-box(n))
      if i < ch.steps.len() {
        cols.push(1fr)
        cells.push(h-arrow(ch.steps.at(i)))
      }
    }
    grid(columns: cols, column-gutter: 4pt, align: horizon, ..cells)
  } else {
    stack(
      dir: ttb,
      spacing: 3pt,
      ..ch
        .nodes
        .enumerate()
        .map(((i, n)) => if i < ch.steps.len() {
          stack(dir: ttb, spacing: 3pt, state-box(n), v-arrow(ch.steps.at(i)))
        } else {
          state-box(n)
        }),
    )
  },
)

// Blast-radius trie rendered as pre-computed box-drawing rows.
#let tree(rows) = block(
  fill: c-soft,
  inset: 7pt,
  radius: 3pt,
  width: 100%,
  {
    set text(font: "DejaVu Sans Mono", size: 7.5pt)
    set par(justify: false)
    for r in rows [#r.prefix#r.label \ ]
  },
)
