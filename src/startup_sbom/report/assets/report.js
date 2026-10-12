(function () {
  'use strict';
  var SVGNS = 'http://www.w3.org/2000/svg';
  // Lookup tables keyed by report-derived ids use Object.create(null): no prototype,
  // so an id such as "__proto__" is just another key.
  var data = JSON.parse(document.getElementById('ssbom-data').textContent);

  function each(list, fn) { Array.prototype.forEach.call(list, fn); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined) { e.textContent = String(text); }
    return e;
  }
  function svg(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, String(attrs[k])); });
    return e;
  }
  function short(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + '\u2026' : s; }

  /* ---------------------------------------------------------- sortable tables */
  function sortKey(cell) {
    var v = cell.getAttribute('data-sort');
    if (v === null) { v = cell.textContent.trim(); }
    if (/^-?\d+(\.\d+)?$/.test(v)) { return [0, parseFloat(v)]; }
    return [1, v.toLowerCase()];
  }
  function sortTable(table, idx, th) {
    var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
    each(th.parentNode.cells, function (c) { c.setAttribute('aria-sort', 'none'); });
    th.setAttribute('aria-sort', dir);
    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(function (a, b) {
      var x = sortKey(a.cells[idx]), y = sortKey(b.cells[idx]);
      var r = x[0] - y[0] || (x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0);
      return dir === 'ascending' ? r : -r;
    });
    rows.forEach(function (r) { body.appendChild(r); });
  }
  each(document.querySelectorAll('table.sortable'), function (table) {
    if (!table.tHead) { return; }
    each(table.tHead.rows[0].cells, function (th, i) {
      th.tabIndex = 0;
      th.setAttribute('aria-sort', 'none');
      th.addEventListener('click', function () { sortTable(table, i, th); });
      th.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); sortTable(table, i, th); }
      });
    });
  });

  /* ---------------------------------------------------------- filters */
  each(document.querySelectorAll('input[data-filter]'), function (input) {
    var table = document.getElementById(input.getAttribute('data-filter'));
    if (!table) { return; }
    input.addEventListener('input', function () {
      var q = input.value.toLowerCase();
      each(table.tBodies[0].rows, function (r) {
        r.hidden = q !== '' && r.textContent.toLowerCase().indexOf(q) < 0;
      });
    });
  });

  /* ---------------------------------------------------------- graph */
  var box = document.getElementById('graph-box');
  var detail = document.getElementById('graph-detail');
  if (!box || !detail) { return; }
  var VIEWS = {
    attack: { kinds: ['entry', 'goal', 'state'], edge: 'step' },
    supply: { kinds: ['package', 'binary', 'service'], edge: 'supply' }
  };

  function layout(nodes, edges) {
    var rank = Object.create(null), ids = nodes.map(function (n) { return n.id; });
    ids.forEach(function (id) { rank[id] = 0; });
    var incoming = Object.create(null);
    edges.forEach(function (e) { incoming[e.target] = (incoming[e.target] || 0) + 1; });
    for (var pass = 0; pass < ids.length; pass++) {
      var changed = false;
      edges.forEach(function (e) {
        if (e.source === e.target) { return; }
        if (rank[e.target] < rank[e.source] + 1 && rank[e.source] + 1 < ids.length) {
          rank[e.target] = rank[e.source] + 1; changed = true;
        }
      });
      if (!changed) { break; }
    }
    var cols = Object.create(null);
    nodes.forEach(function (n) { (cols[rank[n.id]] = cols[rank[n.id]] || []).push(n); });
    var pos = Object.create(null), W = 180, H = 34, GX = 150, GY = 40, TOP = 70, maxRow = 0, maxCol = 0;
    Object.keys(cols).forEach(function (c) {
      cols[c].sort(function (a, b) { return a.label < b.label ? -1 : a.label > b.label ? 1 : 0; });
      cols[c].forEach(function (n, i) {
        pos[n.id] = { x: 20 + Number(c) * (W + GX), y: TOP + i * (H + GY), w: W, h: H,
          rank: Number(c) };
        maxRow = Math.max(maxRow, i); maxCol = Math.max(maxCol, Number(c));
      });
    });
    return { pos: pos, width: 40 + (maxCol + 1) * (W + GX) - GX,
      height: TOP + 70 + (maxRow + 1) * (H + GY) };
  }

  function showNode(n, edges, byId) {
    detail.textContent = '';
    detail.appendChild(el('h4', '', n.label));
    detail.appendChild(el('div', 'small', n.kind + (n.key !== n.label ? ' \u00b7 ' + n.key : '')));
    var out = edges.filter(function (e) { return e.source === n.id; });
    var inc = edges.filter(function (e) { return e.target === n.id; });
    [['Leads to', out, 'target'], ['Reached from', inc, 'source']].forEach(function (g) {
      if (!g[1].length) { return; }
      detail.appendChild(el('h4', '', g[0]));
      var ul = el('ul', 'plain');
      g[1].forEach(function (e) { ul.appendChild(el('li', '', byId[e[g[2]]].label + ' \u2014 ' + e.label)); });
      detail.appendChild(ul);
    });
  }
  function showEdge(e, byId) {
    detail.textContent = '';
    detail.appendChild(el('h4', '', e.label));
    detail.appendChild(el('div', 'small', byId[e.source].label + ' \u2192 ' + byId[e.target].label));
    var ul = el('ul', 'plain');
    if (e.chains && e.chains.length) { ul.appendChild(el('li', '', 'Chains: ' + e.chains.join(', '))); }
    if (e.technique) { ul.appendChild(el('li', '', 'ATT&CK: ' + e.technique)); }
    if (e.kind === 'step') { ul.appendChild(el('li', '', 'Likelihood: ' + Number(e.likelihood).toFixed(2))); }
    if (e.mitigated) { ul.appendChild(el('li', '', 'Mitigated by hardening')); }
    (e.evidence || []).forEach(function (x) { ul.appendChild(el('li', '', 'Evidence: ' + x)); });
    detail.appendChild(ul);
  }

  function draw(view) {
    var spec = VIEWS[view];
    var nodes = data.graph.nodes.filter(function (n) { return spec.kinds.indexOf(n.kind) >= 0; });
    var edges = data.graph.edges.filter(function (e) { return e.kind === spec.edge; });
    box.textContent = '';
    detail.textContent = 'Select a node or an edge for details.';
    if (!nodes.length) { box.appendChild(el('p', 'small', 'No data for this view.')); return; }
    var byId = Object.create(null);
    nodes.forEach(function (n) { byId[n.id] = n; });
    var L = layout(nodes, edges);
    var root = svg('svg', { width: L.width, height: L.height, viewBox: '0 0 ' + L.width + ' ' + L.height,
      role: 'img', 'aria-label': view === 'attack' ? 'Attack graph' : 'Supply-chain blast radius' });
    var defs = svg('defs');
    var marker = svg('marker', { id: 'arrow', viewBox: '0 0 10 10', refX: 10, refY: 5,
      markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' });
    marker.appendChild(svg('path', { d: 'M0,0L10,5L0,10z', 'class': 'arrow' }));
    defs.appendChild(marker);
    root.appendChild(defs);
    var gEdges = svg('g'), gNodes = svg('g'), edgeEls = [], nodeEls = Object.create(null);
    edges.forEach(function (e) {
      var a = L.pos[e.source], b = L.pos[e.target];
      if (!a || !b) { return; }
      var x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2, d, lx, ly;
      var span = b.rank - a.rank;
      if (span === 1) {
        var mx = (x1 + x2) / 2;
        d = 'M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2;
        lx = mx; ly = (y1 + y2) / 2 - 5;
      } else if (span > 1) {
        x1 = a.x + a.w / 2; y1 = a.y; x2 = b.x + b.w / 2; y2 = b.y;
        var top = Math.min(a.y, b.y) - 25 - 12 * span;
        d = 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + top + ' ' + x2 + ',' + top + ' ' + x2 + ',' + y2;
        lx = (x1 + x2) / 2; ly = 0.125 * (y1 + y2) + 0.75 * top - 4;
      } else {
        x1 = a.x + a.w / 2; y1 = a.y + a.h; x2 = b.x + b.w / 2; y2 = b.y + b.h;
        var low = Math.max(a.y, b.y) + a.h + 30 + 12 * Math.abs(span);
        d = 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + low + ' ' + x2 + ',' + low + ' ' + x2 + ',' + y2;
        lx = (x1 + x2) / 2; ly = 0.125 * (y1 + y2) + 0.75 * low + 12;
      }
      var g = svg('g', { 'class': 'edge' + (e.mitigated ? ' mitigated' : '') });
      var p = svg('path', { d: d, 'marker-end': 'url(#arrow)' });
      var t = svg('title'); t.textContent = e.label;
      p.appendChild(t);
      g.appendChild(p);
      var label = svg('text', { x: lx, y: ly, 'text-anchor': 'middle' });
      label.textContent = short(e.label, 30);
      g.appendChild(label);
      g.addEventListener('click', function (ev) {
        ev.stopPropagation(); highlight(null, g); showEdge(e, byId);
      });
      gEdges.appendChild(g);
      edgeEls.push({ e: e, g: g });
    });
    nodes.forEach(function (n) {
      var p = L.pos[n.id];
      var g = svg('g', { 'class': 'node k-' + n.kind, tabindex: 0 });
      g.appendChild(svg('rect', { x: p.x, y: p.y, width: p.w, height: p.h, rx: 6, ry: 6 }));
      var t = svg('text', { x: p.x + p.w / 2, y: p.y + p.h / 2 + 4, 'text-anchor': 'middle' });
      t.textContent = short(n.label, 28);
      g.appendChild(t);
      var title = svg('title'); title.textContent = n.label;
      g.appendChild(title);
      var act = function (ev) { ev.stopPropagation(); highlight(n.id, null); showNode(n, edges, byId); };
      g.addEventListener('click', act);
      g.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { act(ev); } });
      gNodes.appendChild(g);
      nodeEls[n.id] = g;
    });
    function highlight(nodeId, edgeG) {
      Object.keys(nodeEls).forEach(function (k) { nodeEls[k].classList.toggle('hl', k === nodeId); });
      edgeEls.forEach(function (x) {
        x.g.classList.toggle('hl', x.g === edgeG || (nodeId !== null &&
          (x.e.source === nodeId || x.e.target === nodeId)));
      });
    }
    root.addEventListener('click', function () { highlight(null, null); });
    root.appendChild(gEdges);
    root.appendChild(gNodes);
    box.appendChild(root);
  }

  var buttons = document.querySelectorAll('.tabs button[data-view]');
  each(buttons, function (b) {
    b.addEventListener('click', function () {
      each(buttons, function (x) { x.setAttribute('aria-pressed', String(x === b)); });
      draw(b.getAttribute('data-view'));
    });
  });
  draw('attack');
})();
