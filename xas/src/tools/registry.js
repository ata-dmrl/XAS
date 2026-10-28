// src/tools/registry.js
// Tüm araç adapter'larını toplayan merkezi kayıt sistemi.
// Yeni bir araç eklemek = adapters/ altına bir dosya + buraya bir satır.

const NmapAdapter = require("./adapters/nmap");
const ZapAdapter = require("./adapters/zap");
const NbtscanAdapter = require("./adapters/nbtscan");
const NiktoAdapter = require("./adapters/nikto");
const SqlmapAdapter = require("./adapters/sqlmap");
const GobusterAdapter = require("./adapters/gobuster");
const NucleiAdapter = require("./adapters/nuclei");
const TsharkAdapter = require("./adapters/tshark");
const MsfconsoleAdapter = require("./adapters/msfconsole");
const WiresharkAdapter = require("./adapters/wireshark");
const BurpsuiteAdapter = require("./adapters/burpsuite");
const ArmitageAdapter = require("./adapters/armitage");

const adapters = [
  new NmapAdapter(),
  new NbtscanAdapter(),
  new ZapAdapter(),
  new NiktoAdapter(),
  new SqlmapAdapter(),
  new GobusterAdapter(),
  new NucleiAdapter(),
  new TsharkAdapter(),
  new MsfconsoleAdapter(),
  new WiresharkAdapter(),
  new BurpsuiteAdapter(),
  new ArmitageAdapter()
];

// Ada göre adapter bul (büyük/küçük harf duyarsız).
function get(name) {
  if (!name) return null;
  const n = String(name).toLowerCase();
  return adapters.find(a => a.name === n) || null;
}

// Kategoriye göre süz (recon | web | traffic | exploit).
function byCategory(category) {
  return adapters.filter(a => a.category === category);
}

// Belirli bir hedef tipine ("ip" | "url") uygulanabilir, çıktısı ayrıştırılabilen araçlar.
function managedFor(type) {
  return adapters.filter(a => a.mode === "managed" && a.appliesTo(type));
}

// Sadece başlatılabilen (GUI) araçlar.
function launchable() {
  return adapters.filter(a => a.mode === "launch");
}

function all() {
  return adapters.slice();
}

module.exports = { adapters, all, get, byCategory, managedFor, launchable };
