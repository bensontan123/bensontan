/* =======================================================================
   Threat Model Lab — engine + UI
   Imports draw.io / Mermaid / JSON / CSV diagrams (or an image to tag),
   generates STRIDE-LM and RAPID (MITRE TTP) threat models, and renders
   per-technique attack payloads with Sigma + YARA detections.
   All processing is client-side; uploaded diagrams never leave the browser.
   ===================================================================== */
(function () {
  "use strict";
  const KB = window.TLAB;
  if (!KB) return;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
  const elt = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
  const mitreUrl = (id) => { const p = String(id).split("."); return "https://attack.mitre.org/techniques/" + p[0] + (p[1] ? "/" + p[1] : "") + "/"; };

  /* ── state ─────────────────────────────────────────────────────────── */
  let mode = "stride";                 // stride | rapid | ot
  let system = "";
  let comps = [];                      // [{type,name}]
  let flows = [];                      // [{from,to,label}]
  const isOT = () => mode === "ot";
  const typeMap = () => (isOT() ? KB.PURDUE : KB.COMPONENTS);
  const typeOrder = () => (isOT() ? KB.OT_ORDER : KB.IT_TYPE_ORDER);
  const typeLabel = (t) => (typeMap()[t] ? typeMap()[t].label : t);

  /* ── diagram parsers ───────────────────────────────────────────────── */
  async function inflateRaw(b64) {
    const bin = atob(b64.replace(/\s+/g, ""));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    if (typeof DecompressionStream === "undefined") throw new Error("compressed diagram unsupported in this browser");
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    const txt = new TextDecoder().decode(await new Response(stream).arrayBuffer());
    return decodeURIComponent(txt);
  }

  function drawioType(style, value) {
    const s = (style || "").toLowerCase();
    if (/cylinder|shape=datastore|mxgraph.*(database|datastore|storage)|=database/.test(s)) return "datastore";
    if (/umlactor|shape=actor|mxgraph.*(user|users)/.test(s)) return "external";
    if (/mxgraph.*(firewall|router|switch|load.?balancer|gateway)|shape=network/.test(s)) return "network";
    if (/shape=cloud|mxgraph.*cloud/.test(s)) return "external";
    return KB.inferType(value);
  }

  function mxToModel(xml) {
    const doc = new DOMParser().parseFromString(xml, "text/xml");
    if (doc.querySelector("parsererror")) throw new Error("invalid draw.io XML");
    const cells = [...doc.getElementsByTagName("mxCell")];
    const nodes = new Map(); const out = { comps: [], flows: [] };
    cells.forEach((c) => {
      const val = (c.getAttribute("value") || "").replace(/<[^>]+>/g, " ").replace(/&[a-z]+;/gi, " ").replace(/\s+/g, " ").trim();
      if (c.getAttribute("vertex") === "1" && val) {
        nodes.set(c.getAttribute("id"), val);
        out.comps.push({ type: drawioType(c.getAttribute("style"), val), name: val });
      }
    });
    cells.forEach((c) => {
      if (c.getAttribute("edge") === "1") {
        const from = nodes.get(c.getAttribute("source")); const to = nodes.get(c.getAttribute("target"));
        if (from && to) out.flows.push({ from, to, label: (c.getAttribute("value") || "").replace(/<[^>]+>/g, "").trim() });
      }
    });
    const dn = doc.querySelector("diagram");
    return { system: (dn && dn.getAttribute("name")) || "", comps: out.comps, flows: out.flows };
  }

  async function parseDrawio(text) {
    if (/<mxGraphModel/i.test(text)) return mxToModel(text);
    const doc = new DOMParser().parseFromString(text, "text/xml");
    const diagrams = [...doc.getElementsByTagName("diagram")];
    if (!diagrams.length) throw new Error("no <diagram> found");
    let comps = [], flows = [], system = "";
    for (const d of diagrams) {
      const inner = d.textContent.trim();
      const xml = /<mxGraphModel/i.test(inner) ? inner : await inflateRaw(inner);
      const m = mxToModel(xml);
      comps = comps.concat(m.comps); flows = flows.concat(m.flows);
      system = system || d.getAttribute("name") || m.system;
    }
    return { system, comps, flows };
  }

  function mermaidShapeType(open, label) {
    if (open.startsWith("[(")) return "datastore";
    if (open.startsWith("((")) return "external";
    if (open.startsWith("{")) return "process";
    return KB.inferType(label);
  }
  function parseMermaid(text) {
    const nodes = new Map(); const flows = [];
    const nodeRe = /([A-Za-z0-9_]+)(\[\(.+?\)\]|\(\(.+?\)\)|\{\{.+?\}\}|\[\[.+?\]\]|\[.+?\]|\(.+?\)|\{.+?\})/g;
    let m;
    while ((m = nodeRe.exec(text))) {
      const id = m[1]; const raw = m[2];
      const label = raw.replace(/^[\[\(\{]+|[\]\)\}]+$/g, "").replace(/^"|"$/g, "").trim() || id;
      nodes.set(id, { name: label, type: mermaidShapeType(raw, label) });
    }
    text.split(/\r?\n/).forEach((line) => {
      const l = line.replace(/\|[^|]*\|/g, " "); // drop edge labels
      const edgeRe = /([A-Za-z0-9_]+)\s*(?:--+>|--+[xo]|==+>|-\.-+>|--+(?![A-Za-z0-9_]))\s*([A-Za-z0-9_]+)/g;
      let e;
      while ((e = edgeRe.exec(l))) {
        [e[1], e[2]].forEach((id) => { if (!nodes.has(id)) nodes.set(id, { name: id, type: KB.inferType(id) }); });
        flows.push({ from: nodes.get(e[1]).name, to: nodes.get(e[2]).name, label: "" });
      }
    });
    if (!nodes.size) throw new Error("no Mermaid nodes recognised");
    return { system: "", comps: [...nodes.values()].map((n) => ({ type: n.type, name: n.name })), flows };
  }

  function parseJsonModel(text) {
    const d = JSON.parse(text);
    const arr = Array.isArray(d) ? d : d.components || d.comps || [];
    const comps = arr.map((c) => {
      const name = c.name || c.label || c.id || String(c);
      const type = c.type && typeMap()[c.type] ? c.type : KB.inferType(name);
      return { type, name: String(name) };
    });
    const flows = (d.flows || d.edges || []).map((f) => ({ from: f.from || f.source, to: f.to || f.target, label: f.label || "" })).filter((f) => f.from && f.to);
    if (!comps.length) throw new Error("no components in JSON");
    return { system: d.system || d.name || "", comps, flows };
  }

  function parseCsv(text) {
    const comps = [], flows = [];
    text.split(/\r?\n/).forEach((line) => {
      const t = line.trim(); if (!t || /^#/.test(t)) return;
      const p = t.split(",").map((x) => x.trim());
      const head = p[0].toLowerCase();
      if (head === "flow" && p[2]) { flows.push({ from: p[1], to: p[2], label: p[3] || "" }); return; }
      if (head === "type" && /name/i.test(p[1] || "")) return; // header row
      if (p.length >= 2 && typeMap()[head]) { comps.push({ type: head, name: p.slice(1).join(",") }); return; }
      const name = p[p.length - 1]; if (name) comps.push({ type: KB.inferType(name), name });
    });
    if (!comps.length) throw new Error("no components in CSV");
    return { system: "", comps, flows };
  }

  async function parseFile(file) {
    const name = file.name.toLowerCase();
    if (/^image\//.test(file.type) || /\.(png|jpe?g|gif|webp|svg)$/.test(name)) {
      const url = await new Promise((ok, no) => { const r = new FileReader(); r.onload = () => ok(r.result); r.onerror = no; r.readAsDataURL(file); });
      return { image: url, imageName: file.name };
    }
    const text = await file.text();
    if (/\.drawio$|\.xml$/.test(name) || /<mxfile|<mxGraphModel/i.test(text)) return await parseDrawio(text);
    if (/\.json$/.test(name) || /^\s*[\[{]/.test(text)) return parseJsonModel(text);
    if (/\.mmd$|\.mermaid$/.test(name) || /^\s*(graph|flowchart)\b/im.test(text)) return parseMermaid(text);
    if (/\.csv$/.test(name)) return parseCsv(text);
    // last resort: try each
    for (const fn of [parseJsonModel, parseMermaid, parseCsv]) { try { return fn(text); } catch (e) { /* next */ } }
    throw new Error("unrecognised format — use draw.io, Mermaid, JSON or CSV");
  }

  /* ── threat generation ─────────────────────────────────────────────── */
  // IT: [{comp, letter, t, m, ttps:[id]}]
  function itThreats() {
    const rows = [];
    comps.forEach((c) => {
      const def = KB.COMPONENTS[c.type] || KB.COMPONENTS.process;
      Object.keys(def.stride).forEach((letter) => {
        const s = def.stride[letter];
        rows.push({ comp: c, letter, t: s.t, m: s.m, ttps: s.ttps.slice() });
      });
    });
    return rows;
  }
  function otThreats() {
    const rows = [];
    comps.forEach((c) => {
      (KB.PURDUE[c.type] ? KB.PURDUE[c.type].threats : []).forEach((x) => {
        rows.push({ comp: c, ics: x });
      });
    });
    return rows;
  }
  // dataflow components synthesised from imported edges
  function flowComps() {
    return flows.map((f) => ({ type: "dataflow", name: (f.from + " → " + f.to) }));
  }

  /* ── rendering: TTP card ───────────────────────────────────────────── */
  function codeBlock(label, lang, text, cls) {
    return `<div class="code ${cls || ""}">
      <div class="code-top"><span class="code-label">${esc(label)}${lang ? ` · ${esc(lang)}` : ""}</span>
      <button class="code-copy" type="button" aria-label="copy ${esc(label)}">copy</button></div>
      <pre><code>${esc(text)}</code></pre></div>`;
  }
  function ttpCard(id, context) {
    const tech = KB.TECH[id]; if (!tech) return "";
    const a = tech.attack || {};
    const ctx = context && context.length ? `<div class="ttp-ctx">${context.map((c) => `<span>${esc(c)}</span>`).join("")}</div>` : "";
    const tags = [];
    if (a.code) tags.push('<span class="tp off">payload</span>');
    if (tech.sigma) tags.push('<span class="tp def">Sigma</span>');
    if (tech.yara) tags.push('<span class="tp def">YARA</span>');
    return `<details class="ttp">
      <summary>
        <span class="ttp-id">${esc(id)}</span>
        <span class="ttp-name">${esc(tech.name)}</span>
        <span class="ttp-tactic">${esc(tech.tactic)}</span>
        <span class="ttp-tags">${tags.join("")}</span>
        <svg class="ic ttp-caret" aria-hidden="true"><use href="#i-chevron"></use></svg>
      </summary>
      <div class="ttp-body">
        ${ctx}
        <a class="ttp-link" href="${mitreUrl(id)}" target="_blank" rel="noopener noreferrer">${esc(id)} on attack.mitre.org ↗</a>
        <div class="ttp-split">
          <div class="ttp-off">
            <h5><svg class="ic" aria-hidden="true"><use href="#i-sword"></use></svg> Offensive — attack / payload</h5>
            ${a.note ? `<p class="ttp-note">${esc(a.note)}</p>` : ""}
            ${a.code ? codeBlock("payload", a.lang, a.code, "off") : ""}
          </div>
          <div class="ttp-def">
            <h5><svg class="ic" aria-hidden="true"><use href="#i-shield-check"></use></svg> Defensive — detection</h5>
            ${tech.sigma ? codeBlock("Sigma rule", "yaml", tech.sigma, "def") : ""}
            ${tech.yara ? codeBlock("YARA rule", "yara", tech.yara, "def") : ""}
          </div>
        </div>
      </div>
    </details>`;
  }

  /* ── rendering: views ──────────────────────────────────────────────── */
  function strideBadge(letter) {
    const s = KB.STRIDE_LM[letter]; if (!s) return "";
    return `<span class="slm" title="${esc(s.name)} — ${esc(s.prop)}">${letter}</span>`;
  }
  function renderStride(box) {
    const all = comps.concat([]);
    let total = 0; box.innerHTML = "";
    const grouped = {};
    itThreats().forEach((r) => { (grouped[r.comp.name] = grouped[r.comp.name] || { comp: r.comp, rows: [] }).rows.push(r); });
    Object.values(grouped).forEach((g) => {
      const def = KB.COMPONENTS[g.comp.type] || KB.COMPONENTS.process;
      const card = elt("div", "tcard");
      card.innerHTML = `<div class="th"><span class="cn"><svg class="ic" aria-hidden="true"><use href="#i-${def.icon}"></use></svg> ${esc(g.comp.name)}</span><span class="ct">${esc(def.label)}</span></div>`;
      g.rows.forEach((r) => {
        const row = elt("div", "trow");
        row.innerHTML = `<div class="stride-k">${strideBadge(r.letter)} ${esc(KB.STRIDE_LM[r.letter].name)}<small>${esc(KB.STRIDE_LM[r.letter].prop)}</small></div>
          <div><div class="tt">${esc(r.t)}</div><div class="tm-mit"><b>Mitigation:</b> ${esc(r.m)}</div>
          ${r.ttps.map((id) => { total++; return ttpCard(id, []); }).join("")}</div>`;
        card.appendChild(row);
      });
      box.appendChild(card);
    });
    if (!all.length) box.appendChild(elt("div", "empty", "Add or import components to generate a STRIDE-LM model."));
    return total;
  }
  function renderRapid(box) {
    box.innerHTML = "";
    const map = new Map(); // id -> Set(context)
    itThreats().forEach((r) => r.ttps.forEach((id) => {
      if (!map.has(id)) map.set(id, new Set());
      map.get(id).add(`${r.comp.name} · ${KB.STRIDE_LM[r.letter].name}`);
    }));
    if (!map.size) { box.appendChild(elt("div", "empty", "Add or import components to generate a RAPID (MITRE TTP) model.")); return 0; }
    const byTactic = {};
    map.forEach((ctx, id) => { const tac = KB.TECH[id].tactic; (byTactic[tac] = byTactic[tac] || []).push({ id, ctx: [...ctx] }); });
    let total = 0;
    KB.TACTIC_ORDER.forEach((tac) => {
      if (!byTactic[tac]) return;
      const sec = elt("div", "rapid-tac");
      sec.innerHTML = `<div class="rapid-th"><span class="rapid-dot"></span>${esc(tac)}<span class="rapid-n">${byTactic[tac].length}</span></div>`;
      byTactic[tac].forEach((x) => { total++; sec.insertAdjacentHTML("beforeend", ttpCard(x.id, x.ctx)); });
      box.appendChild(sec);
    });
    return total;
  }
  function renderOT(box) {
    box.innerHTML = ""; let total = 0;
    comps.forEach((c) => {
      const lvl = KB.PURDUE[c.type]; if (!lvl) return;
      const card = elt("div", "tcard");
      card.innerHTML = `<div class="th"><span class="cn"><svg class="ic" aria-hidden="true"><use href="#i-plc"></use></svg> ${esc(c.name)}</span><span class="ct">${esc(lvl.label)}</span></div>`;
      lvl.threats.forEach((x) => {
        total++;
        card.insertAdjacentHTML("beforeend", `<div class="trow"><div class="stride-k"><a class="slm-link" href="${mitreUrl(x.id)}" target="_blank" rel="noopener">${esc(x.id)}</a> ${esc(x.name)}<small>${esc(x.tactic)}</small></div>
          <div><div class="tt">${esc(x.t)}</div><div class="tm-mit"><b>Mitigation:</b> ${esc(x.m)}</div></div></div>`);
      });
      box.appendChild(card);
    });
    if (!comps.length) box.appendChild(elt("div", "empty", "Add or import Purdue-level components to generate an ICS threat model."));
    return total;
  }

  /* ── component list + orchestration ────────────────────────────────── */
  function renderComps() {
    const cl = $("tmComps"); cl.innerHTML = "";
    if (!comps.length && !flows.length) { cl.appendChild(elt("li", null, `<span class="cn" style="color:var(--muted)">No components yet — import a diagram, load the sample, or add one.</span>`)); return; }
    comps.forEach((c, i) => {
      const li = elt("li");
      const icon = isOT() ? "plc" : (KB.COMPONENTS[c.type] ? KB.COMPONENTS[c.type].icon : "cpu");
      li.innerHTML = `<svg class="ic" aria-hidden="true"><use href="#i-${icon}"></use></svg><span class="ct">${esc(typeLabel(c.type))}</span><span class="cn">${esc(c.name)}</span>`;
      const rm = elt("button", null, "✕"); rm.type = "button"; rm.setAttribute("aria-label", "remove");
      rm.addEventListener("click", () => { comps.splice(i, 1); render(); });
      li.appendChild(rm); cl.appendChild(li);
    });
    flows.forEach((f, i) => {
      const li = elt("li", "flow-li");
      li.innerHTML = `<svg class="ic" aria-hidden="true"><use href="#i-flow"></use></svg><span class="ct">Data Flow</span><span class="cn">${esc(f.from)} → ${esc(f.to)}</span>`;
      const rm = elt("button", null, "✕"); rm.type = "button"; rm.setAttribute("aria-label", "remove flow");
      rm.addEventListener("click", () => { flows.splice(i, 1); render(); });
      li.appendChild(rm); cl.appendChild(li);
    });
  }
  function render() {
    renderComps();
    // imported flows contribute dataflow threats in IT modes
    const baseComps = comps.slice();
    if (!isOT() && flows.length) comps = baseComps.concat(flowComps());
    const box = $("tmThreats");
    let total = 0;
    if (mode === "stride") total = renderStride(box);
    else if (mode === "rapid") total = renderRapid(box);
    else total = renderOT(box);
    comps = baseComps;
    $("tmCount").textContent = String(total);
    $("tmSysLabel").textContent = system.trim() || "your system";
    const ex = $("tmExpand");
    if (ex) { ex.textContent = "⤢ expand all"; ex.style.display = (mode === "ot" || !total) ? "none" : ""; }
  }

  function setMode(m) {
    if (m === mode) return;
    const wasOT = isOT();
    mode = m;
    [...$("tmModeRow").children].forEach((b) => b.setAttribute("aria-pressed", b.dataset.mode === m ? "true" : "false"));
    if (isOT() !== wasOT) { comps = []; flows = []; }
    populateTypes();
    render();
  }
  function populateTypes() {
    const sel = $("tmType"); sel.innerHTML = "";
    typeOrder().forEach((t) => { const o = document.createElement("option"); o.value = t; o.textContent = typeLabel(t); sel.appendChild(o); });
  }

  function applyModel(model, append) {
    if (!append) { comps = []; flows = []; }
    if (model.system) { system = model.system; $("tmSystem").value = system; }
    (model.comps || []).forEach((c) => { if (typeMap()[c.type] || !isOT()) comps.push({ type: typeMap()[c.type] ? c.type : KB.inferType(c.name), name: c.name }); });
    (model.flows || []).forEach((f) => flows.push(f));
    render();
  }

  /* ── export ────────────────────────────────────────────────────────── */
  function toMarkdown() {
    const title = mode === "ot" ? "OT/ICS Threat Model (Purdue + ATT&CK for ICS)" : mode === "rapid" ? "RAPID Threat Model (MITRE ATT&CK TTPs)" : "STRIDE-LM Threat Model";
    let out = `# ${title}\n\n**System:** ${system || "Untitled"}  \n**Generated:** ${new Date().toISOString().slice(0, 10)} · client-side, no data left the browser\n\n`;
    if (isOT()) {
      comps.forEach((c) => { const lvl = KB.PURDUE[c.type]; if (!lvl) return; out += `## ${c.name} — ${lvl.label}\n`; lvl.threats.forEach((x) => { out += `- **${x.id} ${x.name}** (${x.tactic}): ${x.t}\n  - Mitigation: ${x.m}\n`; }); out += "\n"; });
      return out;
    }
    const base = comps.slice(); const eff = flows.length ? base.concat(flowComps()) : base;
    const saved = comps; comps = eff;
    const rows = itThreats(); comps = saved;
    const grouped = {};
    rows.forEach((r) => (grouped[r.comp.name] = grouped[r.comp.name] || []).push(r));
    Object.keys(grouped).forEach((name) => {
      out += `## ${name}\n`;
      grouped[name].forEach((r) => {
        out += `- **${KB.STRIDE_LM[r.letter].name}** — ${r.t}\n  - Mitigation: ${r.m}\n`;
        r.ttps.forEach((id) => {
          const tech = KB.TECH[id]; out += `  - ${id} ${tech.name} (${tech.tactic})\n`;
          if (tech.attack && tech.attack.code) out += "    - Attack:\n\n      ```" + (tech.attack.lang || "") + "\n" + tech.attack.code.split("\n").map((l) => "      " + l).join("\n") + "\n      ```\n";
          if (tech.sigma) out += "    - Sigma:\n\n      ```yaml\n" + tech.sigma.split("\n").map((l) => "      " + l).join("\n") + "\n      ```\n";
          if (tech.yara) out += "    - YARA:\n\n      ```\n" + tech.yara.split("\n").map((l) => "      " + l).join("\n") + "\n      ```\n";
        });
      });
      out += "\n";
    });
    return out;
  }
  function toJson() {
    const ttpSet = new Set(); comps.forEach((c) => { const d = KB.COMPONENTS[c.type]; if (d) Object.values(d.stride).forEach((s) => s.ttps.forEach((id) => ttpSet.add(id))); });
    return JSON.stringify({ system, mode, generated: new Date().toISOString(), components: comps, flows, techniques: [...ttpSet].map((id) => ({ id, name: KB.TECH[id].name, tactic: KB.TECH[id].tactic })) }, null, 2);
  }
  function copyText(text, btn) {
    const done = () => { const o = btn.textContent; btn.textContent = "✓ copied"; setTimeout(() => (btn.textContent = o), 1400); };
    try { navigator.clipboard.writeText(text).then(done).catch(done); } catch (e) { done(); }
  }

  /* ── wiring ────────────────────────────────────────────────────────── */
  function init() {
    if (!$("tmModeRow")) return;
    populateTypes();
    [...$("tmModeRow").children].forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));

    $("tmSystem").addEventListener("input", (e) => { system = e.target.value; $("tmSysLabel").textContent = system.trim() || "your system"; });
    $("tmAdd").addEventListener("click", () => {
      const name = $("tmName").value.trim(); if (!name) { $("tmName").focus(); return; }
      comps.push({ type: $("tmType").value, name }); $("tmName").value = ""; $("tmName").focus(); render();
    });
    $("tmName").addEventListener("keydown", (e) => { if (e.key === "Enter") $("tmAdd").click(); });
    $("tmClear").addEventListener("click", () => { comps = []; flows = []; system = ""; $("tmSystem").value = ""; clearImage(); render(); });
    $("tmSample").addEventListener("click", () => { clearImage(); applyModel(isOT() ? KB.SAMPLE_OT : KB.SAMPLE_IT, false); });

    // import
    const fi = $("tmFile");
    const handleFiles = async (files) => {
      if (!files || !files.length) return;
      $("tmImportMsg").textContent = "parsing…"; $("tmImportMsg").className = "tm-msg";
      try {
        let added = 0, imaged = false;
        for (const f of files) {
          const res = await parseFile(f);
          if (res.image) { showImage(res.image, res.imageName); imaged = true; }
          else { applyModel(res, added > 0); added += (res.comps || []).length; }
        }
        if (added) { $("tmImportMsg").textContent = `imported ${added} component${added === 1 ? "" : "s"}` + (flows.length ? `, ${flows.length} flow${flows.length === 1 ? "" : "s"}` : ""); $("tmImportMsg").className = "tm-msg ok"; }
        else if (imaged) { $("tmImportMsg").textContent = "image loaded as reference — tag components below"; $("tmImportMsg").className = "tm-msg ok"; }
      } catch (e) {
        $("tmImportMsg").textContent = "could not import: " + e.message; $("tmImportMsg").className = "tm-msg err";
      }
      fi.value = "";
    };
    fi.addEventListener("change", (e) => handleFiles(e.target.files));
    const dz = $("tmDrop");
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
    ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
    dz.addEventListener("drop", (e) => handleFiles(e.dataTransfer.files));

    $("tmCopy").addEventListener("click", (e) => copyText(toMarkdown(), e.currentTarget));
    $("tmJson").addEventListener("click", () => {
      const blob = new Blob([toJson()], { type: "application/json" });
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
      a.download = (system.trim() || "threat-model").replace(/[^a-z0-9]+/gi, "-").toLowerCase() + ".json";
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });

    $("tmExpand").addEventListener("click", (e) => {
      const cards = [...$("tmThreats").querySelectorAll("details.ttp")];
      const anyClosed = cards.some((d) => !d.open);
      cards.forEach((d) => { d.open = anyClosed; });
      e.currentTarget.textContent = anyClosed ? "⤡ collapse all" : "⤢ expand all";
    });

    // delegated copy for code blocks
    $("threatmodel").addEventListener("click", (e) => {
      const b = e.target.closest(".code-copy"); if (!b) return;
      const pre = b.closest(".code").querySelector("pre"); if (pre) copyText(pre.textContent, b);
    });

    render();
  }

  function showImage(url, name) {
    const box = $("tmImage");
    box.innerHTML = `<div class="tm-img-top"><span>reference: ${esc(name || "diagram")}</span><button type="button" id="tmImgClear" class="code-copy">remove</button></div><img alt="uploaded architecture diagram (reference only)" src="${url}">`;
    box.hidden = false;
    $("tmImgClear").addEventListener("click", clearImage);
  }
  function clearImage() { const box = $("tmImage"); box.hidden = true; box.innerHTML = ""; }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
