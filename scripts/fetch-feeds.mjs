// Fetches public security feeds and writes them as JSON into data/ for the
// portfolio page to load. Run by .github/workflows/update-feeds.yml on a
// schedule; run locally with:  node scripts/fetch-feeds.mjs
//
// Sources
//   CISA Known Exploited Vulnerabilities catalogue (JSON) — actively exploited
//   NVD CVE API 2.0 — CVSS for KEV entries, plus recent CRITICAL/HIGH CVEs
//   GitHub Security Advisories (GHSA) — reviewed app / supply-chain advisories
//   FIRST.org EPSS — exploit-prediction scores (enrichment)
//   SingCERT / CSA Singapore, JPCERT/CC, HKCERT (regional alerts, RSS)
//   CISA advisories, SANS ISC, The Hacker News, BleepingComputer, The Record,
//     Krebs on Security (security news / advisories, RSS)
//
// Needs Node 20+ (built-in fetch). No dependencies. An optional GITHUB_TOKEN
// in the environment raises the GitHub advisories rate limit.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "data");
const UA = "portfolio-feed-fetcher/1.1";
const DISPLAY_LIMIT = 48;   // vulnerabilities shown on the dashboard
const NEWS_LIMIT = 24;
const NVD_RECENT_DAYS = 10; // window for "recently published" NVD CVEs
const NVD_RECENT_CAP = 30;  // cap recent NVD items merged into the dashboard

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_KEV_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=2000";
const NVD_RECENT_URL = (sev, start, end) =>
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=${sev}` +
  `&pubStartDate=${encodeURIComponent(start)}&pubEndDate=${encodeURIComponent(end)}&resultsPerPage=500`;
const GHSA_URL = "https://api.github.com/advisories?per_page=50&sort=published&direction=desc&type=reviewed";
const EPSS_URL = (cves) => `https://api.first.org/data/v1/epss?cve=${cves.join(",")}`;

// Regional CERT feeds: every item is kept and tagged with the feed's region.
const REGIONAL_FEEDS = [
  { region: "SG", source: "SingCERT", url: "https://www.csa.gov.sg/alerts-and-advisories/alerts/rss.xml" },
  { region: "JP", source: "JPCERT/CC", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { region: "HK", source: "HKCERT", url: "https://www.hkcert.org/getrss/security-bulletin" },
];
// General news / advisory feeds: used whole for the briefing, and filtered to
// APAC stories (by the keywords below) for the regional news section.
const NEWS_FEEDS = [
  { source: "CISA", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { source: "SANS ISC", url: "https://isc.sans.edu/rssfeed.xml" },
  { source: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { source: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { source: "The Record", url: "https://therecord.media/feed/" },
  { source: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
];
const REGION_KEYWORDS = [
  ["SG", /\bsingapore(an)?\b/i],
  ["MY", /\bmalaysian?\b/i],
  ["ID", /\bindonesian?\b/i],
  ["AU", /\baustralian?\b/i],
  ["NZ", /\bnew zealand\b/i],
  ["JP", /\bjapan(ese)?\b/i],
  ["KR", /\b(south )?korean?\b/i],
  ["CN", /\b(china|chinese)\b/i],
  ["HK", /\bhong kong\b/i],
  ["TW", /\btaiwan(ese)?\b/i],
  ["IN", /\bindian?\b/i],
  ["PH", /\bphilippines?\b|\bfilipino\b/i],
  ["TH", /\bthai(land)?\b/i],
  ["VN", /\bvietnam(ese)?\b/i],
  ["APAC", /\b(apac|asia[- ]pacific|southeast asia|asean|asian?)\b/i],
];

/* ── helpers ─────────────────────────────────────────────────────────── */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function get(url, timeoutMs = 90_000, extraHeaders = {}) {
  const res = await fetch(url, {
    headers: { "User-Agent": UA, Accept: "application/json, application/rss+xml, application/xml, text/xml, */*", ...extraHeaders },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return res;
}

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") {
      const code = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

// Feed text → plain single-line text: unwrap CDATA, drop markup, decode entities.
function plain(s) {
  if (!s) return "";
  let t = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
  t = decodeEntities(t);                    // entity-encoded markup becomes real markup…
  t = t.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]*>/g, " "); // …and is removed
  t = decodeEntities(t);
  return t.replace(/\s+/g, " ").trim();
}

function clip(s, max) {
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const sp = cut.lastIndexOf(" ");
  return (sp > max * 0.6 ? cut.slice(0, sp) : cut).replace(/[\s,;:.\-–—[(]+$/, "") + "…";
}

function tag(block, name) {
  // last non-empty occurrence (some feeds emit an empty <description/> first)
  const re = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "gi");
  let m, val = "";
  while ((m = re.exec(block))) if (m[1].trim()) val = m[1];
  return val;
}

function httpsUrl(s) {
  try {
    const u = new URL(plain(s));
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : "";
  } catch { return ""; }
}

function isoDate(s) {
  const d = new Date(plain(s));
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

// Minimal RSS 2.0 / RDF parser — enough for title, link, date, description.
function parseFeed(xml) {
  const items = [];
  const re = /<item[\s>][\s\S]*?<\/item>/gi;
  let m;
  while ((m = re.exec(xml))) {
    const b = m[0];
    const title = plain(tag(b, "title"));
    const link = httpsUrl(tag(b, "link")) || httpsUrl(tag(b, "guid"));
    if (!title || !link) continue;
    items.push({
      title: clip(title, 160),
      link,
      date: isoDate(tag(b, "pubDate")) || isoDate(tag(b, "dc:date")),
      desc: clip(plain(tag(b, "description")).replace(/\s*\[(\.\.\.|…)\]\s*$/, ""), 240),
    });
  }
  return items;
}

async function fetchFeed(feed) {
  try {
    const items = parseFeed(await (await get(feed.url, 45_000)).text());
    console.log(`  ${feed.source}: ${items.length} items`);
    return items.map((it) => ({ ...it, source: feed.source }));
  } catch (e) {
    console.warn(`  ${feed.source}: skipped (${e.message})`);
    return [];
  }
}

const titleCase = (s) => (s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : "");
const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, PENDING: 0, "": 0 };

/* ── CVSS extraction from an NVD cve object ──────────────────────────── */

function cvssOf(cve) {
  const m = cve.metrics || {};
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = m[key];
    if (!list?.length) continue;
    const pick = list.find((x) => x.type === "Primary") || list[0];
    const d = pick.cvssData || {};
    const score = Number(d.baseScore);
    if (!Number.isFinite(score)) continue;
    const sev = String(d.baseSeverity || pick.baseSeverity || "").toUpperCase();
    const av = d.attackVector || d.accessVector;
    const ac = d.attackComplexity || d.accessComplexity;
    const ui = d.userInteraction;
    return {
      cvss: score,
      severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sev) ? sev : "",
      vector: [av, ac, ui].filter(Boolean).map(titleCase).join(" / "),
      cvssVersion: String(d.version || ""),
    };
  }
  return null;
}

const engDesc = (cve) => (cve.descriptions?.find((d) => d.lang === "en")?.value || "");

/* ── source 1: CISA KEV joined with NVD CVSS ─────────────────────────── */

async function buildKev() {
  console.log("CISA KEV…");
  const kev = await (await get(KEV_URL)).json();
  const sorted = [...kev.vulnerabilities]
    .sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : a.dateAdded > b.dateAdded ? -1 : 0));
  console.log(`  ${kev.vulnerabilities.length} entries, catalogue ${kev.catalogVersion}`);

  const nvd = new Map();
  try {
    console.log("NVD (KEV scores)…");
    const data = await (await get(NVD_KEV_URL, 180_000)).json();
    for (const v of data.vulnerabilities || []) nvd.set(v.cve.id, v.cve);
    console.log(`  ${nvd.size} CVE records`);
  } catch (e) {
    console.warn(`  NVD skipped (${e.message}) — scores will show as pending`);
  }

  const toItem = (k) => {
    const cve = nvd.get(k.cveID);
    const score = cve ? cvssOf(cve) : null;
    return {
      id: k.cveID,
      origin: "KEV",
      product: clip(`${k.vendorProject} ${k.product}`.trim(), 80),
      name: clip(String(k.vulnerabilityName || ""), 140),
      desc: clip(String(k.shortDescription || ""), 300),
      kevAdded: k.dateAdded,
      due: k.dueDate || "",
      ransomware: k.knownRansomwareCampaignUse === "Known",
      published: cve?.published ? cve.published.slice(0, 10) : "",
      cvss: score ? score.cvss : null,
      severity: score?.severity || "PENDING",
      vector: score?.vector || "",
      cvssVersion: score?.cvssVersion || "",
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.cveID)}`,
    };
  };
  return {
    catalogVersion: kev.catalogVersion || "",
    catalogCount: kev.vulnerabilities.length,
    items: sorted.map(toItem),
    ransomware: sorted.filter((k) => k.knownRansomwareCampaignUse === "Known").slice(0, 5).map(toItem),
  };
}

/* ── source 2: recent CRITICAL / HIGH CVEs from NVD ──────────────────── */

async function buildNvdRecent() {
  const end = new Date();
  const start = new Date(Date.now() - NVD_RECENT_DAYS * 86_400_000);
  const fmt = (d) => d.toISOString().slice(0, 23);           // 2026-11-12T07:30:12.587
  const out = new Map();
  for (const sev of ["CRITICAL", "HIGH"]) {
    try {
      console.log(`NVD recent ${sev}…`);
      const data = await (await get(NVD_RECENT_URL(sev, fmt(start), fmt(end)), 180_000)).json();
      for (const v of data.vulnerabilities || []) {
        const cve = v.cve; if (!cve?.id || out.has(cve.id)) continue;
        const score = cvssOf(cve);
        out.set(cve.id, {
          id: cve.id,
          origin: "NVD",
          product: "",
          name: "",
          desc: clip(engDesc(cve), 300),
          published: cve.published ? cve.published.slice(0, 10) : "",
          cvss: score ? score.cvss : null,
          severity: score?.severity || "PENDING",
          vector: score?.vector || "",
          cvssVersion: score?.cvssVersion || "",
          url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`,
        });
      }
      console.log(`  ${data.vulnerabilities?.length || 0} ${sev} CVEs`);
      await sleep(2000); // be gentle on the keyless NVD rate limit
    } catch (e) {
      console.warn(`  NVD recent ${sev} skipped (${e.message})`);
    }
  }
  return [...out.values()]
    .sort((a, b) => (b.cvss || 0) - (a.cvss || 0))
    .slice(0, NVD_RECENT_CAP);
}

/* ── source 3: GitHub Security Advisories (GHSA) ─────────────────────── */

async function buildGhsa() {
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  try {
    console.log("GitHub advisories…");
    const list = await (await get(GHSA_URL, 60_000, headers)).json();
    const items = (Array.isArray(list) ? list : []).map((a) => {
      const sev = String(a.severity || "").toUpperCase();
      const pkg = a.vulnerabilities?.[0]?.package;
      const product = pkg ? clip(`${pkg.ecosystem || ""} ${pkg.name || ""}`.trim(), 80) : "";
      return {
        id: a.cve_id || a.ghsa_id,
        origin: "GHSA",
        product,
        name: clip(String(a.summary || ""), 140),
        desc: clip(String(a.summary || a.description || ""), 300),
        published: a.published_at ? a.published_at.slice(0, 10) : "",
        cvss: Number.isFinite(Number(a.cvss?.score)) && Number(a.cvss.score) > 0 ? Number(a.cvss.score) : null,
        severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sev) ? sev : "PENDING",
        vector: "",
        cvssVersion: "",
        url: a.html_url || (a.cve_id ? `https://nvd.nist.gov/vuln/detail/${a.cve_id}` : ""),
        ghsaId: a.ghsa_id || "",
      };
    }).filter((x) => x.id);
    console.log(`  ${items.length} advisories`);
    return items;
  } catch (e) {
    console.warn(`  GitHub advisories skipped (${e.message})`);
    return [];
  }
}

/* ── enrichment: FIRST.org EPSS exploit-probability ──────────────────── */

async function enrichEpss(items) {
  const cves = [...new Set(items.map((i) => i.id).filter((id) => /^CVE-/i.test(id)))];
  if (!cves.length) return;
  const epss = new Map();
  for (let i = 0; i < cves.length; i += 100) {
    const batch = cves.slice(i, i + 100);
    try {
      const data = await (await get(EPSS_URL(batch), 45_000)).json();
      for (const r of data.data || []) {
        const p = Number(r.epss);
        if (Number.isFinite(p)) epss.set(r.cve, Math.round(p * 1000) / 1000);
      }
    } catch (e) {
      console.warn(`  EPSS batch skipped (${e.message})`);
    }
  }
  if (!epss.size) { console.warn("  EPSS: no scores"); return; }
  for (const it of items) if (epss.has(it.id)) it.epss = epss.get(it.id);
  console.log(`  EPSS scored ${epss.size} CVEs`);
}

/* ── merge all vulnerability sources into one dashboard list ─────────── */

function mergeVulns(kevItems, nvdItems, ghsaItems) {
  const byId = new Map();
  // KEV first — actively exploited, highest authority. Keep its richer fields.
  for (const it of kevItems) if (!byId.has(it.id)) byId.set(it.id, it);
  // Then recent NVD and GHSA, only when the CVE is not already present.
  for (const it of [...nvdItems, ...ghsaItems]) if (!byId.has(it.id)) byId.set(it.id, it);

  const originRank = { KEV: 2, NVD: 1, GHSA: 1 };
  return [...byId.values()].sort((a, b) => {
    const o = (originRank[b.origin] || 0) - (originRank[a.origin] || 0);
    if (o) return o;                                   // KEV (exploited) on top
    const s = (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
    if (s) return s;
    const e = (b.epss || 0) - (a.epss || 0);
    if (e) return e;
    return (b.cvss || 0) - (a.cvss || 0);
  }).slice(0, DISPLAY_LIMIT);
}

/* ── CTI briefing pages ──────────────────────────────────────────────── */

function vulnToBrief(v, cat = "KEV") {
  const tags = [];
  if (v.product) tags.push(v.product);
  if (v.kevAdded) tags.push(`KEV added ${v.kevAdded}`);
  else if (v.published) tags.push(`published ${v.published}`);
  if (v.due) tags.push(`remediate by ${v.due}`);
  if (typeof v.epss === "number") tags.push(`EPSS ${(v.epss * 100).toFixed(1)}%`);
  if (v.ransomware) tags.push("ransomware use");
  return {
    cat,
    sev: v.severity,
    title: `${v.id} — ${v.name || v.product || "advisory"}`,
    desc: v.desc,
    tags,
    link: v.url,
  };
}

function buildCti(merged, kev, nvdItems, ghsaItems, headlines) {
  const briefings = [];
  const kevItems = (kev?.items || []).filter((v) => v.origin === "KEV");

  if (kevItems.length)
    briefings.push({ label: "Newly exploited — latest CISA KEV additions", items: kevItems.slice(0, 5).map((v) => vulnToBrief(v, "KEV")) });

  const ransom = kev?.ransomware || [];
  if (ransom.length)
    briefings.push({ label: "Ransomware-linked exploited vulnerabilities", items: ransom.map((v) => vulnToBrief(v, "Ransomware")) });

  // Most likely to be exploited next — ranked by EPSS across all sources.
  const topEpss = merged.filter((v) => typeof v.epss === "number").sort((a, b) => b.epss - a.epss).slice(0, 5);
  if (topEpss.length)
    briefings.push({ label: "Most likely to be exploited (top EPSS)", items: topEpss.map((v) => vulnToBrief(v, "EPSS")) });

  if (nvdItems.length)
    briefings.push({ label: "High-severity CVEs just published (NVD)", items: nvdItems.slice(0, 5).map((v) => vulnToBrief(v, "NVD")) });

  if (ghsaItems.length)
    briefings.push({ label: "Recently disclosed advisories (GitHub)", items: ghsaItems.slice(0, 5).map((v) => vulnToBrief(v, "GHSA")) });

  if (headlines.length)
    briefings.push({
      label: "Threat headlines",
      items: headlines.slice(0, 6).map((n) => ({ cat: n.source, sev: "NEWS", title: n.title, desc: n.desc, tags: [n.date].filter(Boolean), link: n.link })),
    });

  return briefings;
}

/* ── regional news ───────────────────────────────────────────────────── */

function regionOf(item) {
  const text = `${item.title} ${item.desc}`;
  for (const [code, re] of REGION_KEYWORDS) if (re.test(text)) return code;
  return "";
}

function buildNews(regional, general) {
  const rows = [];
  for (const { feed, items } of regional) {
    for (const it of items.slice(0, 8)) rows.push({ ...it, region: feed.region, cat: "Advisory" });
  }
  for (const it of general) {
    const region = regionOf(it);
    if (region) rows.push({ ...it, region, cat: "News" });
  }
  const seen = new Set();
  return rows
    .filter((r) => (seen.has(r.link) ? false : seen.add(r.link)))
    .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0))
    .slice(0, NEWS_LIMIT)
    .map((r) => ({ date: r.date, region: r.region, cat: r.cat, title: r.title, desc: r.desc, tags: [r.source], link: r.link }));
}

/* ── output ──────────────────────────────────────────────────────────── */

// Writes only when the content changed, so quiet days produce no commit.
async function save(name, payload) {
  const file = join(OUT_DIR, name);
  let prev = null;
  try { prev = JSON.parse(await readFile(file, "utf8")); } catch { /* first run */ }
  const same = prev && JSON.stringify({ ...prev, updated: "" }) === JSON.stringify({ ...payload, updated: "" });
  if (same) { console.log(`${name}: unchanged`); return; }
  await writeFile(file, JSON.stringify(payload, null, 1) + "\n");
  console.log(`${name}: written`);
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const updated = new Date().toISOString();
  let failed = 0;

  let kev = null;
  try { kev = await buildKev(); } catch (e) { failed++; console.error(`KEV feed failed: ${e.message}`); }
  const nvdRecent = await buildNvdRecent();
  const ghsa = await buildGhsa();

  const kevItems = kev?.items || [];
  const merged = mergeVulns(kevItems, nvdRecent, ghsa);
  await enrichEpss(merged);

  console.log("News feeds…");
  const general = (await Promise.all(NEWS_FEEDS.map(fetchFeed))).flat()
    .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  const regional = await Promise.all(REGIONAL_FEEDS.map(async (feed) => ({ feed, items: await fetchFeed(feed) })));

  // The vulnerability dashboard: multi-source, deduped, prioritised.
  if (merged.length) {
    const sources = [...new Set(merged.map((v) => v.origin))];
    await save("vulns.json", {
      updated,
      source: "CISA KEV · NVD · GitHub advisories · EPSS",
      sources,
      catalogVersion: kev?.catalogVersion || "",
      catalogCount: kev?.catalogCount || 0,
      counts: {
        kev: merged.filter((v) => v.origin === "KEV").length,
        nvd: merged.filter((v) => v.origin === "NVD").length,
        ghsa: merged.filter((v) => v.origin === "GHSA").length,
      },
      items: merged,
    });
  } else { failed++; console.error("No vulnerability data — vulns.json left as is"); }

  const briefings = buildCti(merged, kev, nvdRecent, ghsa, general);
  if (briefings.length) await save("cti.json", { updated, source: "CISA KEV, NVD, GitHub advisories, EPSS, security news", briefings });
  else { failed++; console.error("No briefing data — cti.json left as is"); }

  const news = buildNews(regional, general);
  if (news.length) await save("news.json", { updated, source: "SingCERT, JPCERT/CC, HKCERT, CISA, security news feeds", items: news });
  else { failed++; console.error("No regional news — news.json left as is"); }

  if (failed >= 3) process.exit(1); // most datasets failed: surface it as a failed run
}

main().catch((e) => { console.error(e); process.exit(1); });
