/* =======================================================================
   Threat Model Lab — engine + UI
   Four methodologies (domain × framework):
     it-stride : IT · STRIDE-LM        → MITRE TTP (attack + Sigma/YARA)
     it-rapids : IT · RAPIDS scenarios → MITRE TTP (attack + Sigma/YARA)
     ot-stride : OT/ICS Purdue · STRIDE-LM → MITRE TTP
     ot-rapids : OT/ICS Purdue · RAPIDS     → MITRE TTP
   Imports draw.io / Mermaid / JSON / CSV diagrams (or an image to tag).
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
  let mode = "it-stride";              // it-stride | it-rapids | ot-stride | ot-rapids
  let system = "";
  let comps = [];                      // [{type,name}]
  let flows = [];                      // [{from,to,label}]
  const domain = () => (mode.startsWith("ot") ? "ot" : "it");
  const framework = () => (mode.endsWith("rapids") ? "rapids" : "stride");
  const isOT = () => domain() === "ot";
  const typeDefs = () => (isOT() ? KB.PURDUE : KB.COMPONENTS);
  const typeOrder = () => (isOT() ? KB.OT_ORDER : KB.IT_TYPE_ORDER);
  const typeLabel = (t) => (typeDefs()[t] ? typeDefs()[t].label : t);
  const strideMapFor = (type) => (isOT() ? KB.OT_STRIDE[type] : (KB.COMPONENTS[type] || {}).stride);
  const compIcon = (type) => (isOT() ? "plc" : ((KB.COMPONENTS[type] || {}).icon || "cpu"));

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
      const l = line.replace(/\|[^|]*\|/g, " ");
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
      const type = c.type && typeDefs()[c.type] ? c.type : KB.inferType(name);
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
      if (head === "type" && /name/i.test(p[1] || "")) return;
      if (p.length >= 2 && typeDefs()[head]) { comps.push({ type: head, name: p.slice(1).join(",") }); return; }
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
    for (const fn of [parseJsonModel, parseMermaid, parseCsv]) { try { return fn(text); } catch (e) { /* next */ } }
    throw new Error("unrecognised format — use draw.io, Mermaid, JSON or CSV");
  }

  /* ── rendering: code block + TTP card ──────────────────────────────── */
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
    const detects = [];
    if (tech.sigma) detects.push({ label: "Sigma rule", lang: "yaml", code: tech.sigma });
    if (tech.yara) detects.push({ label: "YARA rule", lang: "yara", code: tech.yara });
    (tech.detect || []).forEach((d) => detects.push(d));
    const controls = (tech.defend || []).map((k) => { const d = KB.DEFEND[k]; return d ? { key: k, d } : null; }).filter(Boolean);
    const controlsHtml = controls.map((c) => {
      const lbl = c.d.kind === "attack" ? c.key : "D3FEND";
      return `<a class="ctrl ${c.d.kind}" href="${KB.defendUrl(c.key)}" target="_blank" rel="noopener noreferrer"><span class="ctrl-tag">${esc(lbl)}</span>${esc(c.d.name)}</a>`;
    }).join("");
    const tags = [];
    if (a.code) tags.push('<span class="tp off">payload</span>');
    detects.forEach((d) => { const n = /sigma/i.test(d.label) ? "Sigma" : /yara/i.test(d.label) ? "YARA" : d.label.split(" ")[0]; tags.push(`<span class="tp def">${esc(n)}</span>`); });
    if (controls.some((c) => c.d.kind === "d3")) tags.push('<span class="tp ctrl">D3FEND</span>');
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
            ${a.code ? codeBlock("payload", a.lang, a.code, "off") : `<p class="ttp-withheld">Weaponised payload withheld — detection &amp; mitigation provided.</p>`}
          </div>
          <div class="ttp-def">
            <h5><svg class="ic" aria-hidden="true"><use href="#i-shield-check"></use></svg> Defensive — detection &amp; controls</h5>
            ${controlsHtml ? `<div class="ttp-ctrl"><div class="ctrl-h">Mitigating controls · MITRE D3FEND / ATT&amp;CK</div><div class="ctrl-list">${controlsHtml}</div></div>` : ""}
            ${detects.map((d) => codeBlock(d.label, d.lang, d.code, "def")).join("")}
          </div>
        </div>
      </div>
    </details>`;
  }

  /* ── views ─────────────────────────────────────────────────────────── */
  function strideBadge(letter) {
    const s = KB.STRIDE_LM[letter]; if (!s) return "";
    return `<span class="slm" title="${esc(s.name)} — ${esc(s.prop)}">${letter}</span>`;
  }
  function renderStride(box) {
    box.innerHTML = ""; let total = 0;
    const grouped = {};
    comps.forEach((c) => { (grouped[c.name] = grouped[c.name] || { comp: c, letters: [] }); });
    comps.forEach((c) => {
      const sm = strideMapFor(c.type); if (!sm) return;
      Object.keys(sm).forEach((letter) => grouped[c.name].letters.push({ letter, ...sm[letter] }));
    });
    Object.values(grouped).forEach((g) => {
      const card = elt("div", "tcard");
      card.innerHTML = `<div class="th"><span class="cn"><svg class="ic" aria-hidden="true"><use href="#i-${compIcon(g.comp.type)}"></use></svg> ${esc(g.comp.name)}</span><span class="ct">${esc(typeLabel(g.comp.type))}</span></div>`;
      if (!g.letters.length) card.insertAdjacentHTML("beforeend", `<div class="trow"><div class="stride-k">—</div><div class="tt" style="color:var(--muted)">No STRIDE-LM mapping for this element type.</div></div>`);
      g.letters.forEach((r) => {
        const row = elt("div", "trow");
        row.innerHTML = `<div class="stride-k">${strideBadge(r.letter)} ${esc(KB.STRIDE_LM[r.letter].name)}<small>${esc(KB.STRIDE_LM[r.letter].prop)}</small></div>
          <div><div class="tt">${esc(r.t)}</div><div class="tm-mit"><b>Mitigation:</b> ${esc(r.m)}</div>
          ${(r.ttps || []).map((id) => { total++; return ttpCard(id, []); }).join("")}</div>`;
        card.appendChild(row);
      });
      box.appendChild(card);
    });
    if (!comps.length) box.appendChild(elt("div", "empty", `Add or import components to generate a STRIDE-LM model${isOT() ? " for the Purdue levels" : ""}.`));
    return total;
  }
  function renderRapids(box) {
    box.innerHTML = ""; let total = 0;
    const list = isOT() ? KB.RAPIDS_OT : KB.RAPIDS_IT;
    box.appendChild(elt("div", "scn-note", `Scenario catalogue — the six RAPIDS risk classes for ${isOT() ? "OT / ICS" : "enterprise IT"}, each with its MITRE ATT&amp;CK chain, attack samples and detections.`));
    list.forEach((sc) => {
      const card = elt("div", "scn");
      card.innerHTML = `<div class="scn-head"><span class="scn-key">${esc(sc.key)}</span>
        <svg class="ic scn-ico" aria-hidden="true"><use href="#i-${sc.icon}"></use></svg>
        <span class="scn-name">${esc(sc.name)}</span><span class="scn-n">${sc.ttps.length} TTP${sc.ttps.length === 1 ? "" : "s"}</span></div>
        <p class="scn-desc">${esc(sc.desc)}</p>`;
      sc.ttps.forEach((id) => { total++; card.insertAdjacentHTML("beforeend", ttpCard(id, [])); });
      box.appendChild(card);
    });
    return total;
  }

  /* ── component list + orchestration ────────────────────────────────── */
  function flowComps() { return flows.map((f) => ({ type: "dataflow", name: (f.from + " → " + f.to) })); }
  function renderComps() {
    const cl = $("tmComps"); cl.innerHTML = "";
    const hint = framework() === "rapids" ? "RAPIDS uses the scenario catalogue — components are optional here." : "No components yet — import a diagram, load the sample, or add one.";
    if (!comps.length && !flows.length) { cl.appendChild(elt("li", null, `<span class="cn" style="color:var(--muted)">${esc(hint)}</span>`)); return; }
    comps.forEach((c, i) => {
      const li = elt("li");
      li.innerHTML = `<svg class="ic" aria-hidden="true"><use href="#i-${compIcon(c.type)}"></use></svg><span class="ct">${esc(typeLabel(c.type))}</span><span class="cn">${esc(c.name)}</span>`;
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
    const box = $("tmThreats");
    let total = 0;
    if (framework() === "rapids") {
      total = renderRapids(box);
      $("tmCountWrap").style.display = "none";
    } else {
      const base = comps.slice();
      if (!isOT() && flows.length) comps = base.concat(flowComps());
      total = renderStride(box);
      comps = base;
      $("tmCountWrap").style.display = "";
    }
    $("tmCount").textContent = String(total);
    $("tmSysLabel").textContent = system.trim() || "your system";
    const ex = $("tmExpand");
    if (ex) { ex.textContent = "⤢ expand all"; ex.style.display = total ? "" : "none"; }
    // builder only matters for stride; dim it in rapids
    $("tmBuilder").classList.toggle("muted", framework() === "rapids");
  }
  function populateTypes() {
    const sel = $("tmType"); sel.innerHTML = "";
    typeOrder().forEach((t) => { const o = document.createElement("option"); o.value = t; o.textContent = typeLabel(t); sel.appendChild(o); });
  }
  function setMode(m) {
    if (m === mode) return;
    const prevDomain = domain();
    mode = m;
    [...$("tmModeRow").children].forEach((b) => b.setAttribute("aria-pressed", b.dataset.mode === m ? "true" : "false"));
    if (domain() !== prevDomain) { comps = []; flows = []; }
    populateTypes();
    render();
  }
  function applyModel(model, append) {
    if (!append) { comps = []; flows = []; }
    if (model.system) { system = model.system; $("tmSystem").value = system; }
    (model.comps || []).forEach((c) => { if (typeDefs()[c.type] || !isOT()) comps.push({ type: typeDefs()[c.type] ? c.type : KB.inferType(c.name), name: c.name }); });
    (model.flows || []).forEach((f) => flows.push(f));
    render();
  }

  /* ── export ────────────────────────────────────────────────────────── */
  function techBlock(id, indent) {
    const tech = KB.TECH[id]; if (!tech) return "";
    let o = `${indent}- ${id} ${tech.name} (${tech.tactic})\n`;
    const a = tech.attack || {};
    if (a.note) o += `${indent}  - Attack: ${a.note}\n`;
    if (a.code) o += `${indent}    \`\`\`${a.lang || ""}\n` + a.code.split("\n").map((l) => indent + "    " + l).join("\n") + `\n${indent}    \`\`\`\n`;
    const dets = [];
    if (tech.sigma) dets.push(["Sigma", "yaml", tech.sigma]);
    if (tech.yara) dets.push(["YARA", "", tech.yara]);
    (tech.detect || []).forEach((d) => dets.push([d.label, d.lang, d.code]));
    dets.forEach(([lbl, lng, code]) => { o += `${indent}  - ${lbl}:\n${indent}    \`\`\`${lng || ""}\n` + code.split("\n").map((l) => indent + "    " + l).join("\n") + `\n${indent}    \`\`\`\n`; });
    const ctrls = (tech.defend || []).map((k) => { const d = KB.DEFEND[k]; return d ? `${d.kind === "attack" ? k : "D3FEND"} ${d.name} (${KB.defendUrl(k)})` : null; }).filter(Boolean);
    if (ctrls.length) o += `${indent}  - Mitigating controls (MITRE D3FEND / ATT&CK): ` + ctrls.join("; ") + "\n";
    return o;
  }
  function toMarkdown() {
    const titles = { "it-stride": "STRIDE-LM Threat Model", "it-rapids": "RAPIDS Threat Model (IT)", "ot-stride": "OT/ICS Purdue + STRIDE-LM Threat Model", "ot-rapids": "OT/ICS Purdue + RAPIDS Threat Model" };
    let out = `# ${titles[mode]}\n\n**System:** ${system || "Untitled"}  \n**Generated:** ${new Date().toISOString().slice(0, 10)} · client-side\n\n`;
    if (framework() === "rapids") {
      (isOT() ? KB.RAPIDS_OT : KB.RAPIDS_IT).forEach((sc) => {
        out += `## ${sc.key} — ${sc.name}\n${sc.desc}\n\n`;
        sc.ttps.forEach((id) => { out += techBlock(id, ""); });
        out += "\n";
      });
      return out;
    }
    const base = comps.slice(); const eff = (!isOT() && flows.length) ? base.concat(flowComps()) : base;
    eff.forEach((c) => {
      const sm = strideMapFor(c.type); if (!sm) return;
      out += `## ${c.name} — ${typeLabel(c.type)}\n`;
      Object.keys(sm).forEach((letter) => {
        const r = sm[letter];
        out += `- **${KB.STRIDE_LM[letter].name}** — ${r.t}\n  - Mitigation: ${r.m}\n`;
        (r.ttps || []).forEach((id) => { out += techBlock(id, "  "); });
      });
      out += "\n";
    });
    return out;
  }
  function toJson() {
    const ttps = new Set();
    if (framework() === "rapids") (isOT() ? KB.RAPIDS_OT : KB.RAPIDS_IT).forEach((sc) => sc.ttps.forEach((id) => ttps.add(id)));
    else comps.forEach((c) => { const sm = strideMapFor(c.type); if (sm) Object.values(sm).forEach((r) => (r.ttps || []).forEach((id) => ttps.add(id))); });
    return JSON.stringify({ system, mode, generated: new Date().toISOString(), components: comps, flows, techniques: [...ttps].map((id) => ({ id, name: KB.TECH[id].name, tactic: KB.TECH[id].tactic })) }, null, 2);
  }
  function copyText(text, btn) {
    const done = () => { const o = btn.textContent; btn.textContent = "✓ copied"; setTimeout(() => (btn.textContent = o), 1400); };
    try { navigator.clipboard.writeText(text).then(done).catch(done); } catch (e) { done(); }
  }

  /* ── image reference ───────────────────────────────────────────────── */
  function showImage(url, name) {
    const box = $("tmImage");
    box.innerHTML = `<div class="tm-img-top"><span>reference: ${esc(name || "diagram")}</span><button type="button" id="tmImgClear" class="code-copy">remove</button></div><img alt="uploaded architecture diagram (reference only)" src="${url}">`;
    box.hidden = false;
    $("tmImgClear").addEventListener("click", clearImage);
  }
  function clearImage() { const box = $("tmImage"); box.hidden = true; box.innerHTML = ""; }

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
        if (added) { $("tmImportMsg").textContent = `imported ${added} component${added === 1 ? "" : "s"}` + (flows.length ? `, ${flows.length} flow${flows.length === 1 ? "" : "s"}` : "") + (framework() === "rapids" ? " (switch to a STRIDE-LM mode to model them)" : ""); $("tmImportMsg").className = "tm-msg ok"; }
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
    $("threatmodel").addEventListener("click", (e) => {
      const b = e.target.closest(".code-copy"); if (!b) return;
      const pre = b.closest(".code").querySelector("pre"); if (pre) copyText(pre.textContent, b);
    });
    render();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
