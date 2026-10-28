// src/scanStore.js
// Tarama sonucunu diske yazan/okuyan basit depo. 'start' burayı kullanır,
// 'safe' de buradan okur. Format sade ve kendi kendine yeterlidir.
const fs = require("fs");
const path = require("path");

const REPORTS_DIR = path.resolve(__dirname, "..", "reports");

function sanitize(target) {
  return String(target).replace(/^https?:\/\//i, "").replace(/[^\w.-]/g, "_");
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

// Issue listesini dosyaya yazar, dosya yolunu döner.
function writeScan(target, issues) {
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

  const data = {
    target,
    timestamp: new Date().toISOString(),
    total: issues.length,
    issues: issues.map(i => ({
      id: i.id,
      severity: i.severity,
      source: i.source,
      host: i.host || "",
      ip: i.ip || "",
      port: i.port || null,
      url: i.url || "",
      title: i.title,
      description: i.description,
      fixKey: i.fixKey || null,
      cve: i.cve || null
    }))
  };

  const file = path.join(REPORTS_DIR, `scan-${sanitize(target)}-${timestamp()}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

// Dosyadan tarama okur. { target, timestamp, issues } döner.
function readScan(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  const data = JSON.parse(raw);
  if (!data || !Array.isArray(data.issues)) {
    throw new Error("Geçersiz tarama dosyası (issues dizisi yok).");
  }
  return data;
}

// Bir hedef için scan-*.json dosyalarını en yeni→eski sırada döner.
function findRecentFor(target, n = 10) {
  if (!fs.existsSync(REPORTS_DIR)) return [];
  const prefix = `scan-${sanitize(target)}-`;
  return fs.readdirSync(REPORTS_DIR)
    .filter(f => f.startsWith(prefix) && f.endsWith(".json"))
    .map(f => path.join(REPORTS_DIR, f))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)
    .slice(0, n);
}

function findLatestFor(target) {
  return findRecentFor(target, 1)[0] || null;
}

// Bir bulgunun kimliği (diff için).
function signature(issue) {
  const loc = issue.port || issue.url || issue.ip || issue.host || "";
  return `${issue.source}|${loc}|${issue.fixKey || issue.title}`;
}

// İki bulgu listesini karşılaştırır: eklenen / çözülen / değişmeyen.
function diffScans(oldIssues, newIssues) {
  const oldMap = new Map((oldIssues || []).map(i => [signature(i), i]));
  const newMap = new Map((newIssues || []).map(i => [signature(i), i]));

  const added = [];
  const unchanged = [];
  for (const [sig, issue] of newMap) {
    if (oldMap.has(sig)) unchanged.push(issue);
    else added.push(issue);
  }
  const resolved = [];
  for (const [sig, issue] of oldMap) {
    if (!newMap.has(sig)) resolved.push(issue);
  }
  return { added, resolved, unchanged };
}

module.exports = { writeScan, readScan, findLatestFor, findRecentFor, diffScans, signature, REPORTS_DIR };
