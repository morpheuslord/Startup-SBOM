"""Deterministic visualisations of a report: rich terminal renderables and SVG charts.

:mod:`startup_sbom.viz.terminal` renders explanations as waterfalls, bars, trees and
diagrams that compose inside rich layouts and Textual ``Static`` widgets, honour
``NO_COLOR``, narrow widths and ASCII-only terminals, and pass every untrusted
string through :mod:`startup_sbom.textsafe`.  :mod:`startup_sbom.viz.svg` emits the
same charts as standalone, self-contained SVG documents for the HTML and PDF
reports.
"""
