// src/scope.js
// Yetkili hedef kapsamı (allowlist). Yalnızca burada tanımlı IP/CIDR/domain'lere
// tarama ve yama yapılmasına izin verilir. Kapsam boşsa uyarıyla izin verilir;
// kapsam tanımlıysa dışındaki hedefler reddedilir.
const fs = require("fs");
const path = require("path");
const net = require("net");

const SCOPE_FILE = path.resolve(__dirname, "..", "scope.json");

function load() {
  try {
    const data = JSON.parse(fs.readFileSync(SCOPE_FILE, "utf8"));
    return Array.isArray(data.entries) ? data.entries : [];
  } catch {
    return [];
  }
}

function save(entries) {
  fs.writeFileSync(SCOPE_FILE, JSON.stringify({ entries }, null, 2));
}

function add(entry) {
  const entries = load();
  const e = String(entry).trim();
  if (!e) throw new Error("Boş kapsam girdisi.");
  if (!entries.includes(e)) entries.push(e);
  save(entries);
  return entries;
}

function remove(entry) {
  const entries = load().filter(x => x !== String(entry).trim());
  save(entries);
  return entries;
}

function clear() {
  save([]);
  return [];
}

// Hedeften host kısmını çıkarır (şema/path/port ayıklanır; IP ise olduğu gibi).
function hostOf(target) {
  let t = String(target || "").replace(/^[a-z]+:\/\//i, "").split("/")[0];
  if (net.isIP(t)) return t;
  // host:port → host (IPv6 değilse)
  if (t.includes(":") && net.isIP(t) === 0) t = t.split(":")[0];
  return t;
}

function ipToLong(ip) {
  return ip.split(".").reduce((acc, o) => ((acc << 8) + (Number(o) & 255)) >>> 0, 0);
}

function inCidr(ip, cidr) {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  if (net.isIP(ip) !== 4 || net.isIP(base) !== 4 || isNaN(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToLong(ip) & mask) === (ipToLong(base) & mask);
}

function matchEntry(host, entry) {
  const e = entry.trim();
  if (e.includes("/")) return inCidr(host, e);
  if (e.startsWith("*.")) {
    const suffix = e.slice(1); // ".example.com"
    return host === e.slice(2) || host.endsWith(suffix);
  }
  return host.toLowerCase() === e.toLowerCase();
}

// { allowed, empty, matched } döner.
function isAllowed(target) {
  const entries = load();
  if (entries.length === 0) return { allowed: true, empty: true, matched: null };
  const host = hostOf(target);
  const matched = entries.find(e => matchEntry(host, e)) || null;
  return { allowed: !!matched, empty: false, matched };
}

module.exports = { load, save, add, remove, clear, isAllowed, hostOf, inCidr, matchEntry, SCOPE_FILE };
