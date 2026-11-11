// Fetches public security feeds and writes them as JSON into data/ for the
// portfolio page to load. Run by .github/workflows/update-feeds.yml on a
// schedule; run locally with:  node scripts/fetch-feeds.mjs
//
// Sources
//   CISA Known Exploited Vulnerabilities catalogue (JSON)
//   NVD CVE API 2.0 (CVSS scores for the KEV entries)
//   SingCERT / CSA Singapore, JPCERT/CC, HKCERT (regional alerts, RSS)
//   The Hacker News, BleepingComputer (security news, RSS)
//
// Needs Node 20+ (built-in fetch). No dependencies.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "data");
const UA = "portfolio-feed-fetcher/1.0";
const VULN_LIMIT = 40;
const NEWS_LIMIT = 24;

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_KEV_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=2000";

// Regional CERT feeds: every item is kept and tagged with the feed's region.
const REGIONAL_FEEDS = [
  { region: "SG", source: "SingCERT", url: "https://www.csa.gov.sg/alerts-and-advisories/alerts/rss.xml" },
  { region: "JP", source: "JPCERT/CC", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { region: "HK", source: "HKCERT", url: "https://www.hkcert.org/getrss/security-bulletin" },
];
// General news feeds: used whole for the briefing, and filtered to APAC
// stories (by the keywords below) for the regional news section.
const NEWS_FEEDS = [
  { source: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { source: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
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

async function get(url, timeoutMs = 90_000) {
  const res = await fetch(url, {
    headers: { "User-Agent": UA, Accept: "application/json, application/rss+xml, application/xml, text/xml, */*" },
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

/* ── vulnerabilities: CISA KEV joined with NVD CVSS ──────────────────── */

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

async function buildVulns() {
  console.log("CISA KEV…");
  const kev = await (await get(KEV_URL)).json();
  const sorted = [...kev.vulnerabilities]
    .sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : a.dateAdded > b.dateAdded ? -1 : 0));
  console.log(`  ${kev.vulnerabilities.length} entries, catalogue ${kev.catalogVersion}`);

  // One NVD request returns every KEV-listed CVE with its metrics.
  const nvd = new Map();
  try {
    console.log("NVD…");
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
    items: sorted.slice(0, VULN_LIMIT).map(toItem),
    // most recent entries CISA links to ransomware campaigns (briefing only)
    ransomware: sorted.filter((k) => k.knownRansomwareCampaignUse === "Known").slice(0, 5).map(toItem),
  };
}

/* ── CTI briefing pages ──────────────────────────────────────────────── */

function kevToBrief(v) {
  const tags = [v.product, `KEV added ${v.kevAdded}`];
  if (v.due) tags.push(`remediate by ${v.due}`);
  if (v.ransomware) tags.push("ransomware use");
  return {
    cat: "KEV",
    sev: v.severity,
    title: `${v.id} — ${v.name || v.product}`,
    desc: v.desc,
    tags,
    link: v.url,
  };
}

function buildCti(vulns, headlines) {
  const briefings = [];
  if (vulns.items.length) {
    briefings.push({ label: "Newly exploited — latest CISA KEV additions", items: vulns.items.slice(0, 5).map(kevToBrief) });
    const ransom = vulns.ransomware || [];
    if (ransom.length) briefings.push({ label: "Ransomware-linked exploited vulnerabilities", items: ransom.map(kevToBrief) });
  }
  if (headlines.length) {
    briefings.push({
      label: "Threat headlines",
      items: headlines.slice(0, 6).map((n) => ({ cat: n.source, sev: "NEWS", title: n.title, desc: n.desc, tags: [n.date].filter(Boolean), link: n.link })),
    });
  }
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

  let vulns = null;
  try { vulns = await buildVulns(); } catch (e) { failed++; console.error(`Vulnerability feed failed: ${e.message}`); }

  console.log("News feeds…");
  const general = (await Promise.all(NEWS_FEEDS.map(fetchFeed))).flat()
    .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  const regional = await Promise.all(REGIONAL_FEEDS.map(async (feed) => ({ feed, items: await fetchFeed(feed) })));

  // A dataset that came back empty keeps its previous file rather than blanking the page.
  if (vulns?.items.length) {
    const { ransomware, ...dashboard } = vulns;
    await save("vulns.json", { updated, source: "CISA KEV + NVD", ...dashboard });
  }
  const briefings = buildCti(vulns || { items: [] }, general);
  if (briefings.length) await save("cti.json", { updated, source: "CISA KEV, NVD, security news feeds", briefings });
  else { failed++; console.error("No briefing data — cti.json left as is"); }

  const news = buildNews(regional, general);
  if (news.length) await save("news.json", { updated, source: "SingCERT, JPCERT/CC, HKCERT, security news feeds", items: news });
  else { failed++; console.error("No regional news — news.json left as is"); }

  if (failed === 3) process.exit(1); // every dataset failed: surface it as a failed run
}

main().catch((e) => { console.error(e); process.exit(1); });
