// SPDX-License-Identifier: Apache-2.0

package reporting

// htmlCSS is the complete stylesheet of the HTML report. It contains no
// comments and no external references: its bytes are pinned by hash in the
// Content-Security-Policy.
const htmlCSS = `
:root{--navy:#0B1220;--blue:#3B82F6;--cyan:#06B6D4;--bg:#F8FAFC;--card:#FFFFFF;--text:#0F172A;--muted:#475569;--line:#E2E8F0;--link:#1D4ED8;--focus:#2563EB;--hero:#0B1220;--hero-line:#0B1220;--ok:#10B981;--ok-bg:#D1FAE5;--ok-fg:#065F46;--warn:#F59E0B;--warn-bg:#FEF3C7;--warn-fg:#92400E;--bad:#EF4444;--bad-bg:#FEE2E2;--bad-fg:#991B1B;--unk:#64748B;--unk-bg:#E2E8F0;--unk-fg:#334155;--na:#94A3B8;--na-bg:#F1F5F9;--na-fg:#475569;--info-bg:#CFFAFE;--info-fg:#155E75;--track:#E2E8F0;--shadow:0 1px 2px rgba(15,23,42,.06),0 6px 20px rgba(15,23,42,.06);--radius:14px}
@media (prefers-color-scheme:dark){:root{--bg:#0B1220;--card:#111A2E;--text:#E2E8F0;--muted:#94A3B8;--line:#24304A;--link:#93C5FD;--focus:#60A5FA;--hero:#0F1A33;--hero-line:#24304A;--ok-bg:#053B2E;--ok-fg:#6EE7B7;--warn-bg:#3F2A06;--warn-fg:#FCD34D;--bad-bg:#451313;--bad-fg:#FCA5A5;--unk-bg:#1E293B;--unk-fg:#CBD5E1;--na-bg:#172033;--na-fg:#94A3B8;--info-bg:#083344;--info-fg:#67E8F9;--track:#24304A;--shadow:0 1px 2px rgba(0,0,0,.5)}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;overflow-wrap:break-word;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
[hidden]{display:none!important}
a{color:var(--link);text-underline-offset:2px}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px;border-radius:4px}
.hero :focus-visible{outline-color:#93C5FD}
.wrap{max-width:1120px;margin:0 auto;padding:0 20px}
.skip{position:absolute;left:-9999px;top:8px;background:var(--card);color:var(--link);padding:10px 14px;border-radius:8px;z-index:10}
.skip:focus{left:8px}
.sprite{position:absolute;width:0;height:0;overflow:hidden}
.ic{width:1em;height:1em;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.hero{background:var(--hero);color:#F8FAFC;border-bottom:1px solid var(--hero-line);padding:28px 0 36px}
.brand{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px;font-size:14px;color:#CBD5E1;margin-bottom:26px}
.brand strong{color:#FFFFFF;font-size:16px;letter-spacing:.01em}
.brand .dot{width:10px;height:10px;border-radius:3px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:inline-block;align-self:center}
.hero-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:28px;align-items:center}
.eyebrow{font-size:13px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#93C5FD;margin:0 0 10px}
h1{font-size:18px;font-weight:600;margin:0 0 18px;color:#E2E8F0}
.decision{display:flex;align-items:center;gap:18px}
.badge{flex:none;width:72px;height:72px;border-radius:18px;display:grid;place-items:center;font-size:40px}
.d-block .badge{background:#B91C1C;color:#FFFFFF}
.d-review .badge{background:#F59E0B;color:#0B1220}
.d-allow .badge{background:#10B981;color:#0B1220}
.d-unknown .badge{background:#CBD5E1;color:#0B1220}
.decision-name{font-size:clamp(30px,6vw,46px);font-weight:800;line-height:1.05;letter-spacing:-.01em;margin:0;color:#FFFFFF}
.decision-explain{font-size:18px;margin:14px 0 0;color:#E2E8F0;max-width:60ch}
.reasons{margin:16px 0 0;padding:0 0 0 20px;color:#CBD5E1;font-size:15px;max-width:70ch}
.reasons li{margin:4px 0}
.scorecard{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);border-radius:var(--radius);padding:20px;display:flex;gap:18px;align-items:center}
.dial{width:128px;height:128px;flex:none}
.dial .track{fill:none;stroke:rgba(255,255,255,.16);stroke-width:10}
.dial .value{fill:none;stroke:var(--blue);stroke-width:10;stroke-linecap:round}
.dial text{fill:#FFFFFF;font-weight:700}
.dial .num{font-size:34px}
.dial .den{font-size:13px;fill:#CBD5E1;font-weight:500}
.score-title{font-size:15px;font-weight:600;margin:0;color:#FFFFFF}
.score-note{font-size:14px;color:#CBD5E1;margin:6px 0 0}
.score-none{font-size:22px;font-weight:700;margin:4px 0 0;color:#FFFFFF}
main{padding:8px 0 56px}
section{margin-top:44px}
h2{font-size:22px;line-height:1.25;margin:0 0 6px;letter-spacing:-.01em}
h3{font-size:17px;margin:0 0 4px}
h4{font-size:15px;margin:18px 0 6px}
.lead{color:var(--muted);margin:0 0 18px;max-width:75ch}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:28px}
.metric-label{font-size:14px;color:var(--muted);margin:0}
.metric-value{font-size:28px;font-weight:700;margin:2px 0 0;line-height:1.2}
.metric-note{font-size:14px;color:var(--muted);margin:0 0 10px}
.bar{display:block;width:100%;height:8px;border-radius:99px;overflow:hidden}
.bar .track{fill:var(--track)}
.bar .fill{fill:var(--blue)}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px 24px;margin:0}
.kv div{min-width:0}
.kv dt{font-size:13px;color:var(--muted)}
.kv dd{margin:0;font-weight:500;overflow-wrap:anywhere}
.path{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:.92em;overflow-wrap:anywhere}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:99px;font-size:13px;font-weight:600;line-height:1.4;white-space:nowrap}
.c-verified{background:var(--ok-bg);color:var(--ok-fg)}
.c-partial{background:var(--warn-bg);color:var(--warn-fg)}
.c-failed{background:var(--bad-bg);color:var(--bad-fg)}
.c-unknown,.c-none{background:var(--unk-bg);color:var(--unk-fg)}
.c-na{background:var(--na-bg);color:var(--na-fg)}
.s-critical{background:#991B1B;color:#FFFFFF}
.s-high{background:var(--bad-bg);color:var(--bad-fg)}
.s-medium{background:var(--warn-bg);color:var(--warn-fg)}
.s-low{background:var(--info-bg);color:var(--info-fg)}
.s-info,.s-unrated{background:var(--unk-bg);color:var(--unk-fg)}
.l-block{background:#B91C1C;color:#FFFFFF}
.l-review,.l-warn{background:var(--warn-bg);color:var(--warn-fg)}
.o-block{background:var(--bad-bg);color:var(--bad-fg)}
.o-review{background:var(--warn-bg);color:var(--warn-fg)}
.o-allow{background:var(--ok-bg);color:var(--ok-fg)}
.o-unknown{background:var(--unk-bg);color:var(--unk-fg)}
.tag{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;font-weight:600;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.tag-m{border-color:var(--text);color:var(--text)}
.fix-list{display:grid;gap:16px}
.fix{border-left:6px solid var(--warn);padding-left:18px}
.fix.p-block{border-left-color:var(--bad)}
.fix-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 10px;margin-bottom:6px}
.fix h3{margin:0;font-size:18px}
.fix p{margin:8px 0}
.fix ol{margin:6px 0 0;padding-left:22px}
.fix li{margin:4px 0}
.label{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;display:block;margin-top:12px}
.agent{margin-bottom:16px}
.agent-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-bottom:14px}
.caps{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 0;padding:0;list-style:none}
.tablewrap{overflow-x:auto;margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:15px}
th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}
thead th{font-size:13px;color:var(--muted);font-weight:600;white-space:nowrap}
tbody tr:last-child td,tbody tr:last-child th{border-bottom:0}
tbody th{font-weight:600}
.summary-row{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px;padding:0;list-style:none}
.summary-row li{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px;font-size:14px}
.summary-row b{font-size:18px}
.toolbar,.filters{display:none;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 18px}
.js .toolbar,.js .filters{display:flex}
.field{display:flex;flex-direction:column;gap:4px;font-size:13px;color:var(--muted);font-weight:600}
input[type=search],select,button{font:inherit;font-size:15px;color:var(--text);background:var(--card);border:1px solid var(--unk);border-radius:8px;padding:8px 12px;min-height:42px}
input[type=search]{min-width:min(280px,100%)}
button{cursor:pointer;font-weight:600}
button:hover{border-color:var(--blue)}
.count{font-size:14px;color:var(--muted);margin:0 0 10px}
.domain{margin-top:26px}
.domain-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-bottom:12px}
.domain-head h3{margin:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px;align-items:start}
.tile{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--unk);border-radius:12px;box-shadow:var(--shadow);min-width:0;transition:box-shadow .15s ease}
.tile:hover{box-shadow:0 2px 4px rgba(15,23,42,.08),0 10px 28px rgba(15,23,42,.1)}
.tile.g-verified{border-top-color:var(--ok)}
.tile.g-partial{border-top-color:var(--warn)}
.tile.g-failed{border-top-color:var(--bad)}
.tile.g-na{border-top-color:var(--na)}
.tile[open]{grid-column:1/-1}
.tile>summary{list-style:none;cursor:pointer;padding:14px 16px;display:flex;flex-direction:column;gap:8px;border-radius:10px}
.tile>summary::-webkit-details-marker{display:none}
.tile-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.cid{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;font-weight:600;color:var(--muted)}
.more{margin-left:auto;font-size:13px;color:var(--link);font-weight:600}
.more::after{content:" +"}
.tile[open] .more::after{content:" -"}
.tile-title{font-weight:650;font-size:16px;line-height:1.3}
.tile-meta{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;justify-content:space-between}
.mat{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);font-weight:600}
.pips{display:inline-flex;gap:3px}
.pip{width:10px;height:10px;border-radius:3px;border:1.5px solid var(--unk);display:inline-block}
.pip.on{background:var(--blue);border-color:var(--blue)}
.tile-body{padding:4px 16px 18px;border-top:1px solid var(--line);max-width:90ch}
.tile-body p{margin:8px 0}
.tile-body ul,.tile-body ol{margin:6px 0;padding-left:22px}
.ev{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.ev>li{border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.ev .kv{grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px 18px;font-size:14px}
.ev-sum{margin:0 0 8px;font-weight:600}
.finding-title{font-weight:650}
.finding-meta{font-size:13px;color:var(--muted);margin:4px 0 0}
td details{margin-top:6px;font-size:14px}
td details summary{cursor:pointer;color:var(--link);font-weight:600;border-radius:4px}
td details p{margin:8px 0}
td details ol{margin:6px 0;padding-left:20px}
.empty{padding:18px;color:var(--muted)}
.notice{border-left:6px solid var(--warn)}
.notice h2{margin-bottom:10px}
.notice ul{margin:0;padding-left:20px;max-width:80ch}
.notice li{margin:6px 0}
.plain-list{margin:0;padding-left:20px;max-width:90ch}
.plain-list li{margin:6px 0;overflow-wrap:anywhere}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.legend{margin:0;display:grid;gap:10px}
.legend div{display:grid;grid-template-columns:minmax(150px,230px) 1fr;gap:12px;align-items:start}
.legend dt{margin:0}
.legend dd{margin:0;color:var(--muted)}
footer{border-top:1px solid var(--line);padding:24px 0 40px;color:var(--muted);font-size:14px}
footer p{margin:4px 0}
@media (max-width:820px){.hero-grid{grid-template-columns:1fr}}
@media (max-width:720px){
.badge{width:56px;height:56px;border-radius:14px;font-size:30px}
.decision{gap:14px}
.scorecard{flex-direction:column;align-items:flex-start}
.legend div{grid-template-columns:1fr;gap:4px}
table.stack thead{position:absolute;left:-9999px}
table.stack,table.stack tbody,table.stack tr,table.stack td,table.stack th{display:block;width:100%}
table.stack tr{border:1px solid var(--line);border-radius:12px;padding:8px 4px;margin-bottom:12px;background:var(--card)}
table.stack td,table.stack tbody th{border:0;padding:6px 12px}
table.stack td::before,table.stack tbody th::before{content:attr(data-label);display:block;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.field,input[type=search],select{width:100%}
.card.tablewrap{padding:12px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
@media print{
:root{--bg:#FFFFFF;--card:#FFFFFF;--text:#000000;--muted:#333333;--line:#BBBBBB;--link:#000000;--hero:#FFFFFF;--hero-line:#000000;--ok-bg:#FFFFFF;--ok-fg:#000000;--warn-bg:#FFFFFF;--warn-fg:#000000;--bad-bg:#FFFFFF;--bad-fg:#000000;--unk-bg:#FFFFFF;--unk-fg:#000000;--na-bg:#FFFFFF;--na-fg:#000000;--info-bg:#FFFFFF;--info-fg:#000000;--track:#DDDDDD;--shadow:none}
body{font-size:11pt}
.skip,.toolbar,.filters,.count,.more{display:none!important}
.hero,.hero *{color:#000000!important}
.hero{border-bottom:2px solid #000000;padding:0 0 16px}
.scorecard{border:1px solid #000000;background:#FFFFFF}
.dial .track{stroke:#DDDDDD}
.dial text,.dial .den{fill:#000000}
.badge{border:2px solid #000000;background:#FFFFFF!important;color:#000000!important}
.chip,.s-critical,.l-block{border:1px solid #000000;background:#FFFFFF;color:#000000}
.card,.tile,.fix,.ev>li,tr{break-inside:avoid}
.tile{grid-column:1/-1}
details::details-content{display:block;content-visibility:visible;height:auto}
section{margin-top:24px}
a{text-decoration:none}
}
`

// htmlJS is the complete script of the HTML report. It only toggles the
// hidden and open states of server-rendered elements and updates one counter
// with textContent. It never builds markup from data. It contains no comments:
// its bytes are pinned by hash in the Content-Security-Policy.
const htmlJS = `
(function () {
  "use strict";
  var doc = document;
  doc.documentElement.className = "js";
  function byId(id) { return doc.getElementById(id); }
  function each(list, fn) { for (var i = 0; i < list.length; i++) { fn(list[i]); } }

  var search = byId("f-search"), severity = byId("f-severity"), status = byId("f-status");
  var rows = doc.querySelectorAll("[data-finding]");
  var count = byId("f-count"), none = byId("f-empty"), reset = byId("f-reset");
  function applyFindings() {
    var text = search.value.toLowerCase().trim(), sev = severity.value, st = status.value, shown = 0;
    each(rows, function (row) {
      var ok = (!sev || row.getAttribute("data-severity") === sev) &&
        (!st || row.getAttribute("data-status") === st) &&
        (!text || row.textContent.toLowerCase().indexOf(text) !== -1);
      row.hidden = !ok;
      if (ok) { shown++; }
    });
    count.textContent = "Showing " + shown + " of " + rows.length + " findings";
    none.hidden = shown !== 0;
  }
  if (search && severity && status && count && none) {
    search.addEventListener("input", applyFindings);
    severity.addEventListener("change", applyFindings);
    status.addEventListener("change", applyFindings);
    if (reset) {
      reset.addEventListener("click", function () {
        search.value = ""; severity.value = ""; status.value = "";
        applyFindings();
        search.focus();
      });
    }
    applyFindings();
  }

  var tiles = doc.querySelectorAll("details.tile");
  var group = byId("c-group"), ccount = byId("c-count");
  function applyControls() {
    var want = group.value, shown = 0;
    each(tiles, function (tile) {
      var ok = !want || tile.getAttribute("data-group") === want;
      tile.hidden = !ok;
      if (ok) { shown++; }
    });
    each(doc.querySelectorAll("[data-domain]"), function (domain) {
      domain.hidden = domain.querySelectorAll("details.tile:not([hidden])").length === 0;
    });
    if (ccount) { ccount.textContent = "Showing " + shown + " of " + tiles.length + " controls"; }
  }
  if (group) {
    group.addEventListener("change", applyControls);
    applyControls();
  }
  function setAll(open) { each(tiles, function (tile) { tile.open = open; }); }
  var expand = byId("c-expand"), collapse = byId("c-collapse");
  if (expand) { expand.addEventListener("click", function () { setAll(true); }); }
  if (collapse) { collapse.addEventListener("click", function () { setAll(false); }); }

  function openTarget() {
    var id = window.location.hash.slice(1);
    if (!id) { return; }
    var el = byId(id);
    if (el && el.tagName === "DETAILS") {
      el.hidden = false;
      el.open = true;
      if (el.parentNode && el.parentNode.parentNode) { el.parentNode.parentNode.hidden = false; }
      el.scrollIntoView();
    }
  }
  window.addEventListener("hashchange", openTarget);
  openTarget();

  var reopened = [];
  window.addEventListener("beforeprint", function () {
    reopened = [];
    each(doc.querySelectorAll("details"), function (d) {
      if (!d.open) { d.open = true; reopened.push(d); }
    });
  });
  window.addEventListener("afterprint", function () {
    each(reopened, function (d) { d.open = false; });
    reopened = [];
  });
})();
`

// htmlPageTemplate is the page markup. The placeholders are replaced with
// htmlCSS and htmlJS before the template is parsed.
const htmlPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{{.CSP}}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>{{.ToolName}} report: {{.DecisionName}}</title>
<style>/*CSS*/</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<svg class="sprite" aria-hidden="true" focusable="false">
<symbol id="i-verified" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.8 2.8L16 9.5"/></symbol>
<symbol id="i-allow" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.8 2.8L16 9.5"/></symbol>
<symbol id="i-failed" viewBox="0 0 24 24"><path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z"/><path d="M9 9l6 6M15 9l-6 6"/></symbol>
<symbol id="i-block" viewBox="0 0 24 24"><path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z"/><path d="M9 9l6 6M15 9l-6 6"/></symbol>
<symbol id="i-partial" viewBox="0 0 24 24"><path d="M12 3.5L21.5 20h-19z"/><path d="M12 10v4.5M12 17.2v.3"/></symbol>
<symbol id="i-review" viewBox="0 0 24 24"><path d="M12 3.5L21.5 20h-19z"/><path d="M12 10v4.5M12 17.2v.3"/></symbol>
<symbol id="i-unknown" viewBox="0 0 24 24"><path d="M12 2.5l9.5 9.5-9.5 9.5L2.5 12z"/><path d="M10 10a2 2 0 1 1 3 1.7c-.7.4-1 .8-1 1.6M12 16.4v.2"/></symbol>
<symbol id="i-none" viewBox="0 0 24 24"><path d="M12 2.5l9.5 9.5-9.5 9.5L2.5 12z"/><path d="M10 10a2 2 0 1 1 3 1.7c-.7.4-1 .8-1 1.6M12 16.4v.2"/></symbol>
<symbol id="i-na" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="17" height="17" rx="4"/><path d="M8 12h8"/></symbol>
</svg>

<header class="hero">
<div class="wrap">
<div class="brand"><span class="dot" aria-hidden="true"></span><strong>{{.ToolName}}</strong><span>{{.ToolVersion}}</span><span>Local assessment</span></div>
<div class="hero-grid">
<div class="d-{{.OutcomeKey}}">
<h1>Agent governance assessment</h1>
<p class="eyebrow">Release decision</p>
<div class="decision">
<span class="badge" aria-hidden="true"><svg class="ic" focusable="false"><use href="#i-{{.OutcomeKey}}"/></svg></span>
<p class="decision-name">{{.DecisionName}}</p>
</div>
<p class="decision-explain">{{.DecisionExplain}}</p>
{{if .Reasons}}<ul class="reasons" aria-label="Reasons for the decision">{{range .Reasons}}<li>{{.}}</li>{{end}}{{if .MoreReasons}}<li>And {{.MoreReasons}} more. See what to fix first below.</li>{{end}}</ul>{{end}}
</div>
<div class="scorecard" role="group" aria-label="Assessment maturity score">
{{if .HasScore}}
<svg class="dial" viewBox="0 0 128 128" role="img" aria-label="Assessment maturity {{.ScoreText}}, {{.ScoreNote}}" focusable="false">
<circle class="track" cx="64" cy="64" r="54"/>
<circle class="value" cx="64" cy="64" r="54" stroke-dasharray="{{.DialDash}}" transform="rotate(-90 64 64)"/>
<text class="num" x="64" y="68" text-anchor="middle">{{.ScoreValue}}</text>
<text class="den" x="64" y="88" text-anchor="middle">out of 100</text>
</svg>
<div>
<p class="score-title">Assessment maturity: {{.ScoreText}}</p>
<p class="score-note">This number is {{.ScoreNote}}. It summarizes how much evidence supports the controls. It does not decide the release and it is not a measure of safety.</p>
</div>
{{else}}
<div>
<p class="score-title">Assessment maturity</p>
<p class="score-none">Insufficient evidence</p>
<p class="score-note">No score is shown because no control could be assessed.</p>
</div>
{{end}}
</div>
</div>
</div>
</header>

<main id="main" class="wrap">

{{if .NoAgent}}
<section aria-labelledby="h-noagent">
<div class="card notice">
<h2 id="h-noagent">{{.NoAgentTitle}}</h2>
<ul>{{range .NoAgentLines}}<li>{{.}}</li>{{end}}</ul>
</div>
</section>
{{end}}

{{if .Metrics}}
<div class="metrics">
{{range .Metrics}}
<div class="card">
<p class="metric-label">{{.Label}}</p>
<p class="metric-value">{{.Value}}</p>
<p class="metric-note">{{.Note}}</p>
<svg class="bar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true" focusable="false"><rect class="track" width="100" height="8"/><rect class="fill" width="{{.Percent}}" height="8"/></svg>
</div>
{{end}}
</div>
{{end}}

<section aria-labelledby="h-meta">
<h2 id="h-meta">Scan details</h2>
<div class="card">
<dl class="kv">{{range .Meta}}<div><dt>{{.Key}}</dt><dd>{{.Value}}</dd></div>{{end}}</dl>
</div>
</section>

{{if .Priority}}
<section aria-labelledby="h-fix">
<h2 id="h-fix">What to fix first</h2>
<p class="lead">These controls matter most for the release decision. Blockers come first, then items that need a review, then warnings.</p>
<div class="fix-list">
{{range .Priority}}
<article class="card fix p-{{.LabelKey}}">
<div class="fix-head">
<span class="chip l-{{.LabelKey}}">{{.Label}}</span>
<span class="chip s-{{.SeverityKey}}">{{.Severity}} severity</span>
<span class="chip c-{{.Group}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.Group}}"/></svg>{{.StatusLabel}}</span>
{{if .Mandatory}}<span class="tag tag-m">Mandatory</span>{{end}}
</div>
<h3><span class="cid">{{.ControlID}}</span> {{.Title}}</h3>
{{if .Plain}}<p>{{.Plain}}</p>{{end}}
{{if .Agent}}<p><span class="label">Agent</span>{{.Agent}}</p>{{end}}
<p><span class="label">What was found</span>{{.Found}}</p>
{{if .Where}}<p><span class="label">Where</span><span class="path">{{.Where}}</span></p>{{end}}
{{if .Steps}}<span class="label">How to fix it</span><ol>{{range .Steps}}<li>{{.}}</li>{{end}}</ol>{{end}}
<p><a href="#{{.Anchor}}">Open the control details for {{.ControlID}}</a></p>
</article>
{{end}}
</div>
{{if .MorePriority}}<p class="lead">{{.MorePriority}} more controls need attention. They are listed in the control grid below.</p>{{end}}
</section>
{{end}}

{{if .Agents}}
<section aria-labelledby="h-agents">
<h2 id="h-agents">Agents found</h2>
<p class="lead">An agent is software that uses an AI model to decide which actions to take. The scanner found the agents below. An assessed agent has its own decision and control results.</p>
{{range .Agents}}
<article class="card agent">
<div class="agent-head">
<h3>{{.Name}}</h3>
{{if .Assessed}}<span class="chip o-{{.OutcomeKey}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.OutcomeKey}}"/></svg>{{.DecisionName}}</span><span class="tag">Maturity {{.ScoreText}}</span>{{else}}<span class="tag">Not assessed</span>{{end}}
</div>
<dl class="kv">
<div><dt>Framework</dt><dd>{{.Framework}}</dd></div>
<div><dt>Language</dt><dd>{{.Language}}</dd></div>
<div><dt>Detection</dt><dd>{{.Detection}}</dd></div>
<div><dt>Risk tier</dt><dd>{{.RiskTier}}</dd></div>
<div><dt>Owner</dt><dd>{{.Owner}}</dd></div>
<div><dt>Location</dt><dd class="path">{{.Root}}</dd></div>
<div><dt>Entry point</dt><dd class="path">{{.Entrypoint}}</dd></div>
<div><dt>Tools</dt><dd>{{len .Tools}} ({{.Sensitive}} sensitive)</dd></div>
</dl>
<h4>Capabilities</h4>
{{if .Capabilities}}<ul class="caps">{{range .Capabilities}}<li class="tag">{{.}}</li>{{end}}</ul>{{else}}<p class="lead">No capabilities were detected.</p>{{end}}
{{if .Tools}}
<h4>Tools the agent can use</h4>
<div class="tablewrap">
<table class="stack">
<thead><tr><th scope="col">Tool</th><th scope="col">Kind</th><th scope="col">Sensitive</th><th scope="col">Declared</th><th scope="col">Location</th></tr></thead>
<tbody>
{{range .Tools}}<tr>
<th scope="row" data-label="Tool">{{.Name}}</th>
<td data-label="Kind">{{.Kind}}</td>
<td data-label="Sensitive">{{if .Sensitive}}<span class="chip c-partial"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-partial"/></svg>Sensitive</span>{{if .Why}} {{.Why}}{{end}}{{else}}No{{end}}</td>
<td data-label="Declared">{{if .Declared}}Yes{{else}}No{{end}}</td>
<td data-label="Location" class="path">{{.Where}}</td>
</tr>{{end}}
</tbody>
</table>
</div>
{{end}}
{{if .MCP}}
<h4>MCP connections</h4>
<div class="tablewrap">
<table class="stack">
<thead><tr><th scope="col">Name</th><th scope="col">Transport</th><th scope="col">Target</th><th scope="col">Version pinned</th><th scope="col">Location</th></tr></thead>
<tbody>
{{range .MCP}}<tr>
<th scope="row" data-label="Name">{{.Name}}</th>
<td data-label="Transport">{{.Transport}}</td>
<td data-label="Target" class="path">{{.Target}}</td>
<td data-label="Version pinned">{{if .Pinned}}Yes{{if .Version}} ({{.Version}}){{end}}{{else}}No{{end}}</td>
<td data-label="Location" class="path">{{.Where}}</td>
</tr>{{end}}
</tbody>
</table>
</div>
{{end}}
</article>
{{end}}
</section>

{{if .HasAgents}}
<section aria-labelledby="h-controls">
<h2 id="h-controls">Controls</h2>
<p class="lead">{{.ControlsN}} control results in six domains. Select a control to see why it has its status, the evidence behind it, and how to improve it.</p>
<ul class="summary-row" aria-label="Control counts by group">
{{range .Rollups}}<li><span class="chip c-{{.Key}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.Key}}"/></svg>{{.Label}}</span><b>{{.Count}}</b></li>{{end}}
</ul>
<div class="toolbar">
<label class="field" for="c-group">Show controls
<select id="c-group">
<option value="">All groups</option>
{{range .Rollups}}<option value="{{.Key}}">{{.Label}}</option>{{end}}
</select>
</label>
<button type="button" id="c-expand">Expand all</button>
<button type="button" id="c-collapse">Collapse all</button>
</div>
<p class="count" id="c-count" role="status" aria-live="polite"></p>
{{range .Agents}}{{if .Assessed}}
{{if $.MultiAgent}}<h3>{{.Name}}</h3>{{end}}
{{range .Domains}}
<div class="domain" data-domain>
<div class="domain-head">
{{if $.MultiAgent}}<h4>{{.Name}}</h4>{{else}}<h3>{{.Name}}</h3>{{end}}
{{range .Counts}}<span class="chip c-{{.Key}}">{{.Count}} {{.Label}}</span>{{end}}
</div>
<div class="tiles">
{{range .Controls}}
<details class="tile g-{{.Group}}" data-group="{{.Group}}" id="{{.Anchor}}">
<summary>
<span class="tile-top"><span class="cid">{{.ID}}</span>{{if .Mandatory}}<span class="tag tag-m">Mandatory</span>{{end}}<span class="more">Details</span></span>
<span class="tile-title">{{.Title}}</span>
<span class="tile-meta">
<span class="chip c-{{.Group}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.Group}}"/></svg>{{.StatusLabel}}</span>
<span class="mat"><span class="pips" aria-hidden="true">{{range .Pips}}<i class="pip{{if .}} on{{end}}"></i>{{end}}</span>{{.MaturityText}}</span>
</span>
</summary>
<div class="tile-body">
{{if .Plain}}<p>{{.Plain}}</p>{{end}}
<span class="label">Status</span>
<p><strong>{{.StatusLabel}}.</strong> {{.StatusMeaning}}</p>
{{if .Reason}}<span class="label">Why it has this status</span><p>{{.Reason}}</p>{{end}}
<dl class="kv">
<div><dt>Maturity</dt><dd>{{.MaturityLong}}{{if .Mandatory}} (required: {{.MinMaturity}}){{end}}</dd></div>
<div><dt>Mandatory in this profile</dt><dd>{{if .Mandatory}}Yes{{else}}No{{end}}</dd></div>
<div><dt>Control severity</dt><dd>{{.Severity}}</dd></div>
<div><dt>Highest level a static scan can support</dt><dd>{{.MaxStatic}} of 4</dd></div>
</dl>
<span class="label">Does it apply</span><p>{{.Applicability}}</p>
{{if .NextAction}}<span class="label">Next action</span><p>{{.NextAction}}</p>{{end}}
{{if .Remediation}}<span class="label">How to improve</span><ol>{{range .Remediation}}<li>{{.}}</li>{{end}}</ol>{{end}}
<span class="label">Evidence</span>
{{if .Evidence}}
<ul class="ev">
{{range .Evidence}}<li>
<p class="ev-sum">{{.Summary}}</p>
<dl class="kv">
<div><dt>Source type</dt><dd>{{.Source}}</dd></div>
<div><dt>Result</dt><dd>{{.Result}}</dd></div>
<div><dt>Validity</dt><dd><span class="chip {{if .ValidityOK}}c-verified{{else}}c-partial{{end}}">{{.Validity}}</span>{{if .ValidityWhy}} {{.ValidityWhy}}{{end}}</dd></div>
<div><dt>Integrity</dt><dd>{{.Integrity}}</dd></div>
<div><dt>Observed</dt><dd>{{.Observed}}</dd></div>
<div><dt>Valid until</dt><dd>{{.ValidUntil}}</dd></div>
{{if .Where}}<div><dt>Where</dt><dd class="path">{{.Where}}</dd></div>{{end}}
{{if .Collector}}<div><dt>Collected by</dt><dd class="path">{{.Collector}}</dd></div>{{end}}
</dl>
{{if .Limitations}}<span class="label">Limits of this evidence</span><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{end}}
</li>{{end}}
</ul>
{{else}}<p>No evidence was recorded for this control.</p>{{end}}
{{if .Findings}}<span class="label">Related findings</span><ul>{{range .Findings}}<li>{{.Severity}}: {{.Title}}{{if .Where}} <span class="path">({{.Where}})</span>{{end}}</li>{{end}}</ul>{{end}}
{{if .Limitations}}<span class="label">Limits of this check</span><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>
</details>
{{end}}
</div>
</div>
{{end}}
{{end}}{{end}}
</section>
{{end}}
{{end}}

<section aria-labelledby="h-findings">
<h2 id="h-findings">Findings</h2>
{{if .Findings}}
<p class="lead">A finding is a specific problem the scanner observed. Findings with a file location also appear in the SARIF output.</p>
<ul class="summary-row" aria-label="Findings by severity">
{{range .SeveritySummary}}<li><span class="chip s-{{.Key}}">{{.Label}}</span><b>{{.Count}}</b></li>{{end}}
</ul>
<div class="filters" role="search" aria-label="Filter findings">
<label class="field" for="f-search">Search findings
<input type="search" id="f-search" autocomplete="off" spellcheck="false">
</label>
<label class="field" for="f-severity">Severity
<select id="f-severity">
<option value="">All severities</option>
{{range .SeverityOptions}}<option value="{{.Value}}">{{.Label}}</option>{{end}}
</select>
</label>
<label class="field" for="f-status">Control status
<select id="f-status">
<option value="">All statuses</option>
{{range .StatusOptions}}<option value="{{.Value}}">{{.Label}}</option>{{end}}
</select>
</label>
<button type="button" id="f-reset">Clear filters</button>
</div>
<p class="count" id="f-count" role="status" aria-live="polite"></p>
<div class="card tablewrap">
<table class="stack" aria-label="Findings">
<thead><tr><th scope="col">Severity</th><th scope="col">Control</th><th scope="col">Finding</th><th scope="col">Location</th><th scope="col">Control status</th></tr></thead>
<tbody>
{{range .Findings}}<tr data-finding data-severity="{{.SeverityKey}}" data-status="{{.StatusLabel}}">
<td data-label="Severity"><span class="chip s-{{.SeverityKey}}">{{.Severity}}</span></td>
<td data-label="Control"><span class="cid">{{.ControlID}}</span>{{if .ControlTitle}}<br>{{.ControlTitle}}{{end}}{{if .Domain}}<p class="finding-meta">{{.Domain}}</p>{{end}}</td>
<td data-label="Finding">
<span class="finding-title">{{.Title}}</span>
{{if .Description}}<p class="finding-meta">{{.Description}}</p>{{end}}
<details>
<summary>Why it matters and how to fix it</summary>
{{if .Why}}<p>{{.Why}}</p>{{end}}
{{if .Remediation}}<ol>{{range .Remediation}}<li>{{.}}</li>{{end}}</ol>{{else}}<p>No remediation steps were recorded.</p>{{end}}
{{if .Reproduction}}<p><strong>How to confirm:</strong> {{.Reproduction}}</p>{{end}}
<p class="finding-meta">Rule <span class="path">{{.RuleID}}</span>, {{.Confidence}}{{if .Agent}}, agent {{.Agent}}{{end}}</p>
{{if .Mappings}}<p class="finding-meta">Related standards: {{range $i, $m := .Mappings}}{{if $i}}; {{end}}{{if $m.URL}}<a href="{{$m.URL}}" rel="noopener noreferrer">{{$m.Text}}</a>{{else}}{{$m.Text}}{{end}}{{end}}</p>{{end}}
</details>
</td>
<td data-label="Location" class="path">{{if .Where}}{{.Where}}{{else}}No file location{{end}}</td>
<td data-label="Control status"><span class="chip c-{{.Group}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.Group}}"/></svg>{{.StatusLabel}}</span></td>
</tr>{{end}}
</tbody>
</table>
<p class="empty" id="f-empty" hidden>No findings match the filters.</p>
</div>
{{else}}
<div class="card"><p class="empty">The scan reported no findings. This does not prove that the agent is safe. Check the control statuses and the scan limits below.</p></div>
{{end}}
</section>

<section aria-labelledby="h-limits">
<h2 id="h-limits">Warnings and limits of this scan</h2>
<div class="two">
<div class="card">
<h3>Warnings</h3>
{{if .Warnings}}<ul class="plain-list">{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{else}}<p class="lead">The scan reported no warnings.</p>{{end}}
</div>
<div class="card">
<h3>What this scan could not see</h3>
{{if .Limitations}}<ul class="plain-list">{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{else}}<p class="lead">No limits were recorded.</p>{{end}}
</div>
</div>
</section>

<section aria-labelledby="h-legend">
<h2 id="h-legend">How to read this report</h2>
<div class="two">
{{if .DecisionLegend}}
<div class="card">
<h3>Release decision</h3>
<p class="lead">The decision comes from the mandatory controls of the profile. The score never changes it.</p>
<dl class="legend">{{range .DecisionLegend}}<div><dt><span class="chip o-{{.Key}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.Key}}"/></svg>{{.Label}}</span></dt><dd>{{.Meaning}}</dd></div>{{end}}</dl>
</div>
{{end}}
<div class="card">
<h3>Maturity levels</h3>
<p class="lead">Each control has a maturity from 0 to 4. Stronger evidence gives a higher level.</p>
<dl class="legend">
<div><dt>0</dt><dd>No credited evidence.</dd></div>
<div><dt>1 Declared</dt><dd>A document or setting says the control exists.</dd></div>
<div><dt>2 Implemented</dt><dd>The control is visible in code or configuration.</dd></div>
<div><dt>3 Tested</dt><dd>A test result shows the control works.</dd></div>
<div><dt>4 Operational</dt><dd>Evidence from the running system shows the control works.</dd></div>
</dl>
</div>
<div class="card">
<h3>Control statuses</h3>
<dl class="legend">{{range .StatusLegend}}<div><dt><span class="chip c-{{.Key}}"><svg class="ic" aria-hidden="true" focusable="false"><use href="#i-{{.Key}}"/></svg>{{.Label}}</span></dt><dd>{{.Meaning}}</dd></div>{{end}}</dl>
</div>
<div class="card">
<h3>The score</h3>
<p>The assessment maturity score is {{.ScoreNote}}. It is a weighted summary of the maturity of the applicable controls. A high score with one failed mandatory control still blocks the release.</p>
<p>Unknown is not a pass and not a failure. It means the scanner needs more evidence. A static scan cannot prove that a control works in production.</p>
</div>
</div>
</section>

</main>

<footer>
<div class="wrap">
<p>Generated by {{.ToolName}} {{.ToolVersion}}. {{.Disclaimer}}</p>
<p>This report was produced locally. It loads nothing from the network.</p>
</div>
</footer>
<script>/*JS*/</script>
</body>
</html>
`
