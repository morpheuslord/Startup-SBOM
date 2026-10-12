// Startup-SBOM PDF report (Typst 0.15).  All scan, advisory and AI content
// arrives as JSON values through sys.inputs (or fixed-name files in a private
// compile root for the CLI engine) and is placed as text, never as markup.
// No package imports, so compilation never touches the network.
#import "components.typ": *

// One input accessor: sys.inputs when the Python engine supplies it, else the
// fixed-name file in the compile root when the CLI engine sets mode=files.
#let load(key, file) = if key in sys.inputs {
  sys.inputs.at(key)
} else if sys.inputs.at("mode", default: "") == "files" {
  str(read(file))
} else { "" }

#let d = json(bytes(load("data", "data.json")))

#set document(
  title: d.title,
  author: d.meta.tool + " " + d.meta.tool_version,
  keywords: ("SBOM", "vulnerability", "threat model", "attack chain", "supply chain"),
  date: auto,
)
#set text(font: "Libertinus Serif", size: 9pt, fill: c-ink, lang: "en")
#set par(justify: true, leading: 0.58em)
#show raw: set text(font: "DejaVu Sans Mono", size: 8pt)
#show link: set text(fill: c-accent)
#set heading(numbering: "1.1")
#show heading.where(level: 1): set text(size: 14pt)
#show heading.where(level: 2): set text(size: 11pt)
#show heading.where(level: 3): set text(size: 9.5pt)
#set page(
  paper: sys.inputs.at("paper", default: "a4"),
  margin: (x: 17mm, top: 16mm, bottom: 18mm),
  footer: context {
    set text(6.8pt, fill: c-mute)
    grid(
      columns: (1fr, auto),
      [#d.meta.tool #d.meta.tool_version · scan #d.meta.scan_id],
      counter(page).display("1 / 1", both: true),
    )
  },
)

// Shared sub-layouts ---------------------------------------------------------
#let th(body) = text(7.5pt, weight: "bold", body)

#let ssvc-trace(tr, title) = if tr != none {
  block(breakable: true, above: 6pt, below: 4pt)[
    #text(8pt, weight: "bold", title)
    #text(8pt)[ — tree #mono(tr.tree, size: 7.5pt), row #str(tr.row) → *#tr.outcome*]
    #table(
      columns: (auto, auto, 1fr, auto),
      stroke: (x, y) => (bottom: 0.3pt + c-rule),
      fill: (x, y) => if y == 0 { c-fill },
      inset: (x: 4pt, y: 3.5pt),
      table.header(th[Decision point], th[Value], th[Rationale], th[Source]),
      ..tr
        .path
        .map(n => (
          text(7.5pt, n.point),
          {
            text(7.5pt, weight: "bold", n.value)
            if n.alternatives.len() > 0 {
              text(6.5pt, fill: c-mute, " vs " + n.alternatives.join(", "))
            }
          },
          text(7.5pt, n.rationale),
          chip(n.source),
        ))
        .flatten(),
    )
    #if tr.flips.len() > 0 [
      #text(7pt, fill: c-mute)[What would change the outcome: #tr.flips.join(" · ")]
    ]
  ]
}

#let intel-block(x) = block(
  width: 100%,
  fill: c-soft,
  stroke: 0.5pt + c-rule,
  radius: 3pt,
  inset: 7pt,
  breakable: true,
  above: 6pt,
)[
  #text(7.5pt, weight: "bold")[Threat intelligence]
  #text(6.8pt, fill: c-mute)[ — third-party sources; exploit and PoC references are unverified]
  #for p in x.summary [#par(text(8pt, p))]
  #if x.bundle != none {
    let b = x.bundle
    block(above: 4pt, {
      chip[maturity: #b.maturity]
      [ ]
      chip(tone: if b.exploitation == "active" { "critical" })[exploitation: #b.exploitation]
      if b.kev [ #chip(tone: "critical")[CISA KEV] ]
      if b.epss_last != none [ #chip[EPSS #b.epss_last] ]
      if b.sources.len() > 0 [ #chip[sources: #b.sources.join(", ")] ]
      [ ]
      chip[fetched #b.fetched]
      if b.errors > 0 [ #chip(tone: "medium")[#str(b.errors) source error(s)] ]
    })
    if b.exploits.len() > 0 {
      block(above: 4pt)[
        #text(7.5pt, weight: "bold")[Public exploit modules]
        #for e in b.exploits [
          #block(above: 2pt, {
            text(7.5pt)[• #e.source: ]
            if e.url != none { link(e.url, mono(e.id, size: 7.5pt)) } else { mono(e.id, size: 7.5pt) }
            if e.title != none { text(7.5pt, fill: c-mute, " — " + e.title) }
            if e.verified == true { text(6.5pt, fill: c-mute, " (source-verified)") }
          })
        ]
      ]
    }
    if b.poc_count > 0 {
      block(above: 4pt, {
        text(7.5pt, weight: "bold")[#str(b.poc_count) public PoC repositories]
        text(6.8pt, fill: c-mute)[ (untrusted, never executed): ]
        b.pocs.map(p => {
          if p.url != none { link(p.url, mono(p.name, size: 7.5pt)) } else { mono(p.name, size: 7.5pt) }
          text(6.8pt, fill: c-mute, " ★" + str(p.stars))
        }).join(", ")
      })
    }
    if b.vendors.len() > 0 {
      block(above: 4pt)[
        #text(7.5pt, weight: "bold")[Vendor status (as published)]
        #for v in b.vendors [
          #block(above: 2pt, {
            text(7.5pt)[• #v.vendor: ]
            if v.status != none { text(7.5pt, weight: "bold", v.status) }
            if v.severity != none { text(7.5pt, fill: c-mute, " · severity " + v.severity) }
            if v.statement != none { text(7.5pt, fill: c-mute, " — " + v.statement) }
            if v.url != none { text(7.5pt)[ (#link(v.url)[advisory])] }
          })
        ]
      ]
    }
    if b.advisories.len() > 0 {
      block(above: 4pt, {
        text(7.5pt, weight: "bold")[Further reading: ]
        b.advisories.map(a => {
          if a.url != none { link(a.url, text(7.5pt, a.title)) } else { text(7.5pt, a.title) }
          if a.site != none { text(6.8pt, fill: c-mute, " (" + a.site + ")") }
        }).join(text(7.5pt, " · "))
      })
    }
  }
]

#let whatif-row(w) = (
  {
    set par(justify: false)
    for f in w.fixes {
      block(above: 2pt, {
        evref(f.ref)
        if f.action != "" { text(7.5pt, fill: c-mute, " — " + f.action) }
      })
    }
  },
  text(7.5pt, w.before),
  text(7.5pt, weight: "bold", w.after),
  { set par(justify: false); set text(7.5pt); ref-list(w.chains) },
  { set par(justify: false); set text(7.5pt); ref-list(w.threats) },
  text(7pt, fill: c-mute, w.method + (if w.note != "" { " — " + w.note } else { "" })),
)

// ------------------------------------------------------------------- cover
#page(margin: 0pt, footer: none)[
  #block(width: 100%, height: 31%, fill: c-ink, inset: (x: 20mm, y: 16mm))[
    #set par(justify: false)
    #set text(fill: white)
    #text(9pt, tracking: 2.2pt, fill: rgb("#9ca3af"), upper(d.meta.tool)) \
    #v(5mm)
    #text(23pt, weight: "bold", d.title) \
    #v(2.5mm)
    #text(10.5pt, fill: rgb("#d1d5db"), d.os.name)
  ]
  #block(inset: (x: 20mm, top: 8mm, bottom: 6mm))[
    #grid(
      columns: (34mm, 1fr),
      row-gutter: 5.5pt,
      ..field("Target", mono(d.meta.target) + text(7.5pt, fill: c-mute, "  (" + d.meta.target_kind + ")")),
      ..if d.meta.image != none { field("Image", mono(d.meta.image)) } else { () },
      ..if d.meta.digest != none { field("Digest", mono(d.meta.digest)) } else { () },
      ..if d.meta.platform != none { field("Platform", mono(d.meta.platform)) } else { () },
      ..field("Scan ID", mono(d.meta.scan_id)),
      ..field("Started", d.meta.started),
      ..if d.meta.finished != none { field("Finished", d.meta.finished) } else { () },
      ..field(
        "OS support",
        if d.os.eol_status == "eol" {
          pill("end of life", "critical")
          text(8.5pt)[ #if d.os.eol_date != none [ since #d.os.eol_date]]
        } else if d.os.eol_status == "supported" {
          [supported#if d.os.eol_date != none [ until #d.os.eol_date]]
        } else { [unknown] },
      ),
      ..field("Tool", d.meta.tool + " " + d.meta.tool_version + " · schema " + d.meta.schema),
    )
    #v(7mm)
    #outline(title: [Contents], depth: 2)
  ]
]
#counter(page).update(1)

// -------------------------------------------------------- executive summary
= Executive summary
#mark-section("summary")

#grid(columns: (1fr,) * 4, column-gutter: 6pt, row-gutter: 6pt, ..d.kpis.map(kpi))

#if d.coverage.limitations.len() > 0 {
  v(4pt)
  note-box(tone: "medium")[
    *Coverage limitations.* Absence of a finding is not evidence of absence:
    #d.coverage.limitations.join(" · ")
  ]
}

#if d.system != none [
  == System risk
  #grid(
    columns: (auto, 1fr),
    column-gutter: 8mm,
    align: horizon,
    {
      text(26pt, weight: "bold", fill: tone-color(d.system.tone), d.system.risk)
      text(9pt, fill: c-mute, " / 100")
    },
    meter(d.system.risk_frac, d.system.tone),
  )
  #text(7pt, fill: c-mute)[Method #d.system.method · #d.system.formula]
  #figure(
    driver-chart(d.system.drivers),
    kind: image,
    caption: [Top drivers of system risk (contribution in points and share).],
    alt: d.system.alt,
  )
  #if d.system.pareto != "" [
    #text(7.5pt, fill: c-mute)[80% of the system risk concentrates in: #d.system.pareto.]
  ]
]

== Finding distribution
#grid(
  columns: (1fr, 1fr),
  column-gutter: 8mm,
  figure(
    bar-chart(d.severity.rows),
    kind: image,
    caption: [Vulnerabilities by severity.],
    alt: d.severity.alt,
  ),
  figure(
    bar-chart(d.ssvc.rows),
    kind: image,
    caption: [Threats by SSVC decision.],
    alt: d.ssvc.alt,
  ),
)

// ------------------------------------------------------------------ threats
#pagebreak(weak: true)
= Threats in system context
#mark-section("threats")

#if d.threats.len() == 0 [
  No threats were derived from this scan.
]
#for t in d.threats [
  #[#heading(level: 2)[#t.id — #t.title] #label(t.anchor)]
  #block(above: 4pt, {
    pill(t.severity, t.severity)
    [ ]
    if t.ssvc != none { pill("SSVC " + t.ssvc.decision, t.ssvc.tone); [ ] }
    chip[risk *#t.risk* / 100]
    [ ]
    chip[#t.reach]
    [ ]
    chip[confidence #t.confidence]
    if t.exposed [ #chip(tone: "high")[network-exposed] ]
  })
  #grid(
    columns: (32mm, 1fr),
    row-gutter: 4pt,
    ..field("Package", mono(t.package)),
    ..field("Vulnerability", {
      evref(t.vuln)
      if t.vuln_url != none { text(7.5pt)[ · #link(t.vuln_url)[public reference]] }
    }),
    ..field("Attacker state", [#chip(mono(t.pre, size: 7.5pt)) → #chip(mono(t.post, size: 7.5pt))]),
    ..field("Vector", t.vector + " · privileges required: " + t.privileges),
    ..if t.run_as != none { field("Runs as", mono(t.run_as)) } else { () },
    ..if t.consequences.len() > 0 { field("Consequences", t.consequences.join(", ")) } else { () },
    ..if t.listeners.len() > 0 {
      field("Listeners", t.listeners.map(x => mono(x, size: 7.5pt)).join(", "))
    } else { () },
    ..if t.techniques.len() > 0 {
      field("ATT&CK", t.techniques.map(x => {
        if x.url != none { link(x.url, chip[#x.id #x.name]) } else { chip[#x.id #x.name] }
      }).join(" "))
    } else { () },
    ..if t.stride.len() > 0 { field("STRIDE", t.stride.map(s => chip(s)).join(" ")) } else { () },
  )
  #if t.paths.len() > 0 [
    #block(above: 5pt)[
      #text(8pt, weight: "bold")[Reachability]
      #for p in t.paths [
        #block(above: 2pt, mono(p.join(" → "), size: 7.5pt))
      ]
    ]
  ]
  #for p in t.narrative [#par(text(p))]
  #if t.ssvc != none [
    #block(above: 5pt, {
      text(8pt, weight: "bold")[SSVC decision inputs: ]
      t.ssvc.inputs.map(i => chip[#i.point: *#i.value*]).join(" ")
    })
    #ssvc-trace(t.ssvc.trace, "Decision path (coordinator tree)")
    #ssvc-trace(t.ssvc.bod, "Decision path (deployer timeline tree)")
  ]
  #if t.chart != none [
    #figure(
      waterfall(t.chart),
      kind: image,
      caption: [Why this score: factor contributions to risk #t.risk.],
      alt: t.chart.alt,
    )
    #if t.chart.formula != "" [
      #text(7pt, fill: c-mute)[#t.chart.method · #t.chart.formula#if not t.chart.exact [ (approximate decomposition)]]
    ]
    #if t.chart.limits.len() > 0 [
      #text(7pt, fill: c-mute)[Knowledge limits: #t.chart.limits.join(" · ")]
    ]
  ]
  #if t.mitigations.len() > 0 [
    #block(above: 5pt)[
      #text(8pt, weight: "bold")[Mitigations in place]
      #list(..t.mitigations.map(m => text(8.5pt, m)))
    ]
  ]
  #if t.remediation.len() > 0 [
    #block(above: 5pt)[
      #text(8pt, weight: "bold")[Remediation. ]
      #for p in t.remediation [#text(8.5pt, p) ]
    ]
  ]
  #if t.intel != none { intel-block(t.intel) }
]
#if d.other_threats.len() > 0 [
  == Further threats
  #table(
    columns: (auto, 1fr, auto, auto, auto, auto),
    stroke: (x, y) => (bottom: 0.3pt + c-rule),
    fill: (x, y) => if y == 0 { c-fill },
    inset: (x: 4pt, y: 3.5pt),
    table.header(th[Threat], th[Title], th[Vulnerability], th[Risk], th[SSVC], th[Reachability]),
    ..d.other_threats
      .map(t => (
        evref(t.ref),
        text(7.5pt, t.title),
        evref(t.vuln),
        text(7.5pt, t.risk),
        text(7.5pt, t.decision),
        text(7.5pt, t.reach),
      ))
      .flatten(),
  )
]

// ------------------------------------------------------------ attack chains
= Attack chains
#mark-section("chains")

#if d.chains.len() == 0 [
  No multi-step attack chains were ranked for this system.
]
#for ch in d.chains [
  #[#heading(level: 2)[#ch.id — #ch.entry → #ch.goal] #label(ch.anchor)]
  #block(above: 4pt, {
    pill("SSVC " + ch.decision, ch.tone)
    [ ]
    chip[score *#ch.score* / 100]
    [ ]
    chip[likelihood #ch.likelihood]
    [ ]
    chip[impact #ch.impact]
    if ch.mitigated [ #chip(tone: "down")[mitigated] ]
  })
  #figure(
    chain-diagram(ch),
    kind: image,
    caption: [Privilege-state chain #ch.id.],
    alt: ch.alt,
  )
  #for (i, st) in ch.steps.enumerate() [
    #block(above: 3pt, {
      text(8pt, weight: "bold")[Step #str(i + 1) — #st.title.]
      set text(7.5pt)
      if st.technique != none {
        [ ]
        if st.technique.url != none { link(st.technique.url, chip[#st.technique.id #st.technique.name]) } else { chip[#st.technique.id #st.technique.name] }
      }
      [ likelihood #st.likelihood.]
      if st.threat != none [ Threat #evref(st.threat).]
      if st.vuln != none [ Via #evref(st.vuln).]
      if st.service != none [ Service #mono(st.service, size: 7.5pt).]
      if st.evidence.len() > 0 {
        text(7pt, fill: c-mute)[ Evidence: #st.evidence.join(" · ")]
      }
      if st.mitigated_by.len() > 0 {
        linebreak()
        text(7.5pt, fill: c-ok)[Mitigated by: #st.mitigated_by.join(" · ")]
      }
    })
  ]
  #if ch.chart != none [
    #figure(
      waterfall(ch.chart),
      kind: image,
      caption: [Why this score: factor contributions for #ch.id.],
      alt: ch.chart.alt,
    )
  ]
  #for p in ch.narrative [#par(text(p))]
]
#if d.other_chains.len() > 0 [
  == Further chains
  #table(
    columns: (auto, 1fr, auto, auto, auto),
    stroke: (x, y) => (bottom: 0.3pt + c-rule),
    fill: (x, y) => if y == 0 { c-fill },
    inset: (x: 4pt, y: 3.5pt),
    table.header(th[Chain], th[Path], th[Steps], th[Score], th[SSVC]),
    ..d.other_chains
      .map(c => (
        evref(c.ref),
        mono(c.path, size: 7.5pt),
        text(7.5pt, str(c.steps)),
        text(7.5pt, c.score),
        text(7.5pt, c.decision),
      ))
      .flatten(),
  )
]

// ------------------------------------------------------------- remediation
#if d.fixes != none [
  = Remediation planning
  #mark-section("fixes")

  #if d.fixes.plans.len() > 0 [
    == Minimal fix plan
    #for w in d.fixes.plans [
      #block(width: 100%, stroke: 0.5pt + c-rule, radius: 3pt, inset: 8pt, above: 5pt)[
        #grid(
          columns: (auto, 1fr, auto, 1fr),
          column-gutter: 5pt,
          align: horizon,
          text(7.5pt)[risk #w.before],
          meter(w.before_frac, "high"),
          text(7.5pt, weight: "bold")[→ #w.after],
          meter(w.after_frac, "down"),
        )
        #block(above: 4pt, {
          for f in w.fixes {
            block(above: 2pt, {
              evref(f.ref)
              if f.action != "" { text(8pt, " — " + f.action) }
            })
          }
        })
        #text(7.5pt)[Breaks chains: #ref-list(w.chains) · resolves threats: #ref-list(w.threats)]
        #text(7pt, fill: c-mute)[ (#w.method#if w.note != "" [ — #w.note])]
      ]
    ]
  ]
  #if d.fixes.what_if.len() > 0 [
    == What-if: single fixes
    #table(
      columns: (1fr, auto, auto, auto, auto, auto),
      stroke: (x, y) => (bottom: 0.3pt + c-rule),
      fill: (x, y) => if y == 0 { c-fill },
      inset: (x: 4pt, y: 3.5pt),
      table.header(th[Fix], th[Risk before], th[After], th[Chains broken], th[Threats resolved], th[Method]),
      ..d.fixes.what_if.map(whatif-row).flatten(),
    )
  ]
  #if d.fixes.fixes.len() > 0 [
    == Fix catalogue
    #table(
      columns: (auto, auto, auto, 1fr, auto, auto),
      stroke: (x, y) => (bottom: 0.3pt + c-rule),
      fill: (x, y) => if y == 0 { c-fill },
      inset: (x: 4pt, y: 3.5pt),
      table.header(th[Fix], th[Kind], th[Target], th[Action], th[Resolves], th[Breaks]),
      ..d.fixes
        .fixes
        .map(f => (
          [#metadata(none)#label(f.anchor)#mono(f.id, size: 7.5pt)],
          text(7.5pt, f.kind),
          mono(f.target, size: 7.5pt),
          text(7.5pt, f.action),
          text(7.5pt, str(f.resolves)),
          text(7.5pt, str(f.breaks)),
        ))
        .flatten(),
    )
  ]
]

// ------------------------------------------------------------- supply chain
= Supply chain
#mark-section("supply")

#if (d.supply.vendors.len() == 0 and d.supply.findings.len() == 0 and d.supply.blast.len() == 0) [
  No supply-chain observations were recorded.
]
#if d.supply.vendors.len() > 0 [
  == Vendors
  #table(
    columns: (1fr, auto, auto, auto, auto, auto, auto, auto),
    stroke: (x, y) => (bottom: 0.3pt + c-rule),
    fill: (x, y) => if y == 0 { c-fill },
    inset: (x: 4pt, y: 3.5pt),
    align: (left, right, right, right, right, right, right, right),
    table.header(th[Vendor], th[Pkgs], th[Boot], th[Svcs], th[Vulns], th[Crit], th[High], th[KEV]),
    ..d.supply
      .vendors
      .map(v => (
        text(7.5pt, v.vendor),
        text(7.5pt, str(v.packages)),
        text(7.5pt, str(v.boot)),
        text(7.5pt, str(v.services)),
        text(7.5pt, str(v.vulns)),
        text(7.5pt, weight: if v.critical > 0 { "bold" } else { "regular" }, str(v.critical)),
        text(7.5pt, str(v.high)),
        text(7.5pt, str(v.kev)),
      ))
      .flatten(),
  )
]
#if d.supply.findings.len() > 0 [
  == Provenance findings
  #for f in d.supply.findings [
    #block(above: 4pt, {
      [#metadata(none)#label(f.anchor)]
      pill(f.severity, f.severity)
      text(8.5pt, weight: "bold")[ #f.title]
      linebreak()
      text(7.5pt, fill: c-mute)[#mono(f.id, size: 7pt) · #f.kind · subject ]
      mono(f.subject, size: 7.5pt)
      if f.detail != "" { linebreak(); text(8pt, f.detail) }
    })
  ]
]
#if d.supply.blast.len() > 0 [
  == Blast radius
  #for b in d.supply.blast [
    #block(above: 5pt, {
      [#metadata(none)#label(b.anchor)]
      text(8.5pt, weight: "bold", b.package)
      if b.vendor != none { text(7.5pt, fill: c-mute, " · vendor " + b.vendor) }
      text(7.5pt, fill: c-mute)[ · blast score #b.score · #str(b.services) service(s), #str(b.binaries) binarie(s)]
      if b.vulns.len() > 0 { linebreak(); text(7.5pt)[Vulnerabilities: #ref-list(b.vulns)] }
    })
    #tree(b.rows)
  ]
]

// ---------------------------------------------------------------- services
= Boot services
#mark-section("services")

#if d.services.len() == 0 [
  No automatically started services were discovered.
] else [
  #table(
    columns: (auto, auto, auto, auto, auto, 1fr),
    stroke: (x, y) => (bottom: 0.3pt + c-rule),
    fill: (x, y) => if y == 0 { c-fill },
    inset: (x: 4pt, y: 3.5pt),
    table.header(th[Service], th[Init], th[Activation], th[User], th[Exposure], th[Listeners]),
    ..d.services
      .map(s => (
        [#metadata(none)#label(s.anchor)#mono(s.name, size: 7.5pt)],
        text(7.5pt, s.init),
        text(7.5pt, s.activation),
        text(7.5pt, weight: if s.root { "bold" } else { "regular" },
          fill: if s.root { tones.high } else { c-ink }, s.user),
        text(7.5pt, s.exposure),
        {
          set par(justify: false)
          for l in s.listeners {
            block(above: 1.5pt, {
              mono(l.text, size: 7pt)
              if l.network { text(6.5pt, fill: tones.high, weight: "bold", " network") }
            })
          }
        },
      ))
      .flatten(),
  )
]
#if d.services_manual > 0 [
  #text(7.5pt, fill: c-mute)[#str(d.services_manual) further service(s) are installed but not started automatically.]
]

// --------------------------------------------------------------- inventory
#pagebreak(weak: true)
= Vulnerability inventory
#mark-section("vulns")

#if d.vulns.len() == 0 [
  No vulnerabilities were matched against the installed packages.
] else [
  #set par(justify: false)
  #table(
    columns: (auto, auto, auto, auto, auto, 1fr),
    stroke: (x, y) => (bottom: 0.3pt + c-rule),
    fill: (x, y) => if y == 0 { c-fill },
    inset: (x: 3.5pt, y: 3.5pt),
    table.header(th[ID], th[Severity], th[Package], th[Installed → fixed], th[EPSS], th[Context]),
    ..d.vulns
      .map(v => (
        {
          [#metadata(none)#label(v.anchor)]
          set par(justify: false)
          if v.url != none { link(v.url, mono(v.id, size: 7pt)) } else { mono(v.id, size: 7pt) }
          if v.kev { linebreak(); pill("KEV", "critical") }
        },
        pill(v.severity, v.severity),
        mono(v.package, size: 7pt),
        mono(v.installed + " → " + (if v.fixed == none { "none" } else { v.fixed }), size: 7pt),
        text(7.5pt, v.epss),
        {
          set text(7pt)
          text(fill: c-mute, v.reach)
          if v.status != "affected" { text(fill: c-mute, " · " + v.status) }
          if v.summary != "" { linebreak(); text(v.summary) }
        },
      ))
      .flatten(),
  )
  #if d.vulns_truncated > 0 [
    #text(7.5pt, fill: c-mute)[#str(d.vulns_truncated) further row(s) omitted; the attached report.json carries every finding.]
  ]
]

// -------------------------------------------------------------- AI analysis
#if d.ai != none [
  #pagebreak(weak: true)
  = AI analysis
  #mark-section("ai")

  #note-box(tone: "medium")[
    *Machine-generated content.* Produced by #mono(d.ai.provider, size: 7.5pt) ·
    #mono(d.ai.model, size: 7.5pt) on #d.ai.generated over report input
    #mono(d.ai.input_sha256, size: 7.5pt)…
    #if d.ai.agents.len() > 0 [ (agents: #d.ai.agents.join(", "))]
    for a #d.ai.audience audience. #d.ai.disclaimer
  ]
  #block(above: 5pt, {
    text(8pt, weight: "bold")[Grounding check: ]
    if d.ai.grounding.passed { pill("passed", "down") } else { pill("failed", "high") }
    text(8pt)[ · #d.ai.grounding.ratio of claims grounded · #str(d.ai.claims) structured claim(s) machine-checked]
  })
  #if d.ai.unknown.len() > 0 {
    note-box(tone: "high")[
      *#str(d.ai.unknown.len()) cited id(s) do not exist in this report* and are
      flagged where they appear: #d.ai.unknown.map(u => mono(u, size: 7.5pt)).join(", ")
    ]
  }
  #if d.ai.grounding.issues.len() > 0 [
    #table(
      columns: (auto, auto, 1fr),
      stroke: (x, y) => (bottom: 0.3pt + c-rule),
      fill: (x, y) => if y == 0 { c-fill },
      inset: (x: 4pt, y: 3.5pt),
      table.header(th[Claim], th[Issue], th[Detail]),
      ..d.ai
        .grounding
        .issues
        .map(i => (text(7.5pt, i.claim), text(7.5pt, i.code), text(7.5pt, i.detail)))
        .flatten(),
    )
  ]

  == Assessment summary
  #for p in d.ai.summary [#par(text(p))]

  #if d.ai.findings.len() > 0 [
    == Prioritised findings
    #for f in d.ai.findings [
      #block(width: 100%, stroke: 0.5pt + c-rule, radius: 3pt, inset: 7pt, above: 5pt, breakable: true)[
        #pill(f.priority, f.tone)
        #text(9pt, weight: "bold")[ #f.title]
        #if not f.agrees [ #chip(tone: "high")[diverges from scanner] ]
        #text(7pt, fill: c-mute)[ confidence #f.confidence]
        #if f.threat != none [
          #block(above: 3pt, text(7.5pt)[Scanner threat: #evref(f.threat)])
        ]
        #for p in f.rationale [#par(text(8.5pt, p))]
        #if f.evidence.len() > 0 [
          #block(above: 3pt, {
            text(7.5pt, fill: c-mute)[Evidence: ]
            f.evidence.map(e => {
              evref(e)
              text(6.8pt, fill: c-mute, " (" + e.kind + (if e.note != none { ": " + e.note } else { "" }) + ")")
            }).join(", ")
          })
        ]
        #if f.counterfactuals.len() > 0 [
          #block(above: 3pt)[
            #text(7.5pt, fill: c-mute)[What would change this finding:]
            #list(..f.counterfactuals.map(c => text(7.5pt)[#c.condition → #c.effect]))
          ]
        ]
      ]
    ]
  ]
  #if d.ai.plan.len() > 0 [
    == Remediation plan (AI-suggested)
    #for s in d.ai.plan [
      #block(above: 5pt, breakable: true)[
        #text(8.5pt, weight: "bold")[#str(s.n). #s.title]
        #text(7pt, fill: c-mute)[ confidence #s.confidence]
        #if s.commands.len() > 0 [
          #block(above: 3pt, raw(s.commands.join("\n"), block: true))
          #text(6.8pt, fill: c-mute)[Suggested commands only — review before use; never executed by the tool.]
        ]
        #for p in s.rationale [#par(text(8pt, p))]
        #block(above: 2pt, text(7.5pt)[Fixes: #ref-list(s.fixes) · evidence: #ref-list(s.evidence)])
      ]
    ]
  ]
  #if d.ai.caveats.len() > 0 [
    #block(above: 5pt)[
      #text(8pt, weight: "bold")[Model-stated caveats]
      #list(..d.ai.caveats.map(c => text(8pt, c)))
    ]
  ]
]

// ---------------------------------------------------- coverage and warnings
= Coverage and limitations
#mark-section("coverage")

#grid(
  columns: (40mm, 1fr),
  row-gutter: 5pt,
  ..field("Package databases", if d.coverage.databases.len() > 0 { d.coverage.databases.map(chip).join(" ") } else { [—] }),
  ..field("Init systems", if d.coverage.init_systems.len() > 0 { d.coverage.init_systems.map(chip).join(" ") } else { [—] }),
  ..field("Vulnerability sources", if d.coverage.sources.len() > 0 { d.coverage.sources.map(chip).join(" ") } else { [—] }),
  ..field("Ecosystems", if d.coverage.ecosystems.len() > 0 { d.coverage.ecosystems.map(chip).join(" ") } else { [—] }),
  ..field("Network", if d.coverage.offline { [offline scan — no feeds were fetched] } else { [online feeds used] }),
)
#if d.coverage.limitations.len() > 0 [
  #block(above: 5pt)[
    #text(8pt, weight: "bold")[Limitations]
    #list(..d.coverage.limitations.map(x => text(8.5pt, x)))
  ]
]
#if d.warnings.len() > 0 [
  == Scanner warnings
  #list(..d.warnings.map(w => text(8pt, w)))
  #if d.warnings_truncated > 0 [
    #text(7.5pt, fill: c-mute)[#str(d.warnings_truncated) further warning(s) are in the attached report.json.]
  ]
]

// ----------------------------------------------------------------- appendix
#pagebreak(weak: true)
= Appendix

== Methodology
#mark-section("methodology")

This report was produced by a static, root-confined analysis of the target
file system: package databases, init-system configuration and ELF linkage are
parsed in place; nothing from the target is ever executed, mounted or written.
Vulnerabilities are matched by source package and exact distribution ecosystem,
then enriched with EPSS, CISA KEV and, when enabled, public threat
intelligence. Each matched vulnerability is reversed into system context
(reachability, attacker precondition → postcondition, run-as user, exposure
and hardening) and scored on a 0–100 scale; a forward-chaining rule engine
assembles multi-step attack chains over privilege states.

Every score in this report is explainable: risk scores ship an exact additive
factor decomposition (baseline + sum of contributions = total, the "why this
score" charts), SSVC decisions carry their full decision path with the
alternatives at each point, and minimal fix plans state which chains and
threats each fix removes.

#block(above: 5pt)[
  #text(8pt, weight: "bold")[Mapping to NIST IR 8312 (Four Principles of Explainable AI)]
  #table(
    columns: (auto, 1fr),
    stroke: (x, y) => (bottom: 0.3pt + c-rule),
    fill: (x, y) => if y == 0 { c-fill },
    inset: (x: 4pt, y: 3.5pt),
    table.header(th[Principle], th[How this report meets it]),
    text(7.5pt)[Explanation], text(7.5pt)[Every risk score, SSVC decision and attack chain is accompanied by the evidence and factor breakdown that produced it.],
    text(7.5pt)[Meaningful], text(7.5pt)[Factors carry plain-language labels and narratives; decision paths show the rejected alternatives next to each choice.],
    text(7.5pt)[Explanation accuracy], text(7.5pt)[Decompositions are exact by construction and machine-validated; AI claims are checked against report ids ("grounding").],
    text(7.5pt)[Knowledge limits], text(7.5pt)[Coverage limitations, per-finding confidence grades and knowledge-limit notes state where the analysis stops.],
  )
]

== Data notices
#mark-section("notices")

- MITRE ATT&CK® — technique names and ids © The MITRE Corporation; ATT&CK is a
  registered trademark of The MITRE Corporation. Technique mappings draw on the
  Center for Threat-Informed Defense (CTID) attack-flow and CVE-mapping work.
  See #link("https://attack.mitre.org")[attack.mitre.org].
- EPSS — Exploit Prediction Scoring System scores courtesy of FIRST.org, used
  under the EPSS usage terms. See #link("https://www.first.org/epss")[first.org/epss].
- CISA KEV and SSVC — Known Exploited Vulnerabilities catalog data and
  Stakeholder-Specific Vulnerability Categorization decision trees from the US
  Cybersecurity and Infrastructure Security Agency.
  See #link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")[cisa.gov].
- OS end-of-life dates from the endoflife.date community project.
- Threat-intelligence sections (exploit modules, proof-of-concept repositories,
  vendor statements, articles) quote third-party, unverified material; treat
  them as leads, not conclusions.
- The complete machine-readable findings travel with this PDF as attached
  files (PDF/A-3 "data" relationship) when the archival profile is used.

// --------------------------------------------- machine-readable attachments
#let att-report = load("attach-report", "attach-report.json")
#if att-report != "" {
  pdf.attach(
    "report.json",
    bytes(att-report),
    relationship: "data",
    mime-type: "application/json",
    description: "Native Startup-SBOM report (schema " + d.meta.schema + ")",
  )
}
#let att-ai = load("attach-ai", "attach-ai.json")
#if att-ai != "" {
  pdf.attach(
    "ai-assessment.json",
    bytes(att-ai),
    relationship: "data",
    mime-type: "application/json",
    description: "AI assessment (structured, grounding-checked)",
  )
}
