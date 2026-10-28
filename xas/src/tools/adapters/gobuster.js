// src/tools/adapters/gobuster.js
// Dizin/dosya keşfi — erişilebilir yolları ve açık yönetim panellerini bulur.
const fs = require("fs");
const path = require("path");
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

// Hassas kabul edilen yol kalıpları → yüksek önem + admin_panel rehberi.
const SENSITIVE_RE = /(admin|login|dashboard|manage|manager|phpmyadmin|wp-admin|cpanel|webmail|console|portal)/i;

// Olası varsayılan kelime listeleri (ilk bulunan kullanılır).
const DEFAULT_WORDLISTS = [
  "/usr/share/wordlists/dirb/common.txt",
  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
];

class GobusterAdapter extends Adapter {
  constructor() {
    super({
      name: "gobuster",
      label: "Gobuster",
      category: "web",
      binary: "gobuster",
      versionCmd: "gobuster version",
      aptPackage: "gobuster",
      installUrl: "https://github.com/OJ/gobuster",
      mode: "managed",
      targetTypes: ["url"]
    });
    this.wordlist = null; // opts.wordlist ile override edilebilir
  }

  resolveWordlist(preferred) {
    if (preferred && fs.existsSync(preferred)) return preferred;
    if (this.wordlist && fs.existsSync(this.wordlist)) return this.wordlist;
    return DEFAULT_WORDLISTS.find(w => fs.existsSync(w)) || null;
  }

  // gobuster dir çıktısını ayrıştırır: "/admin  (Status: 200) [Size: 1234]"
  parse(text, startId, baseUrl) {
    const issues = [];
    let id = startId;
    const base = (baseUrl || "").replace(/\/+$/, "");
    const re = /^(\/\S*)\s+\(Status:\s*(\d{3})\)/;

    for (const raw of String(text).split(/\r?\n/)) {
      const line = raw.trim();
      const m = line.match(re);
      if (!m) continue;

      const route = m[1];
      const status = Number(m[2]);
      const sensitive = SENSITIVE_RE.test(route);

      issues.push(new Issue({
        id: id++,
        source: "gobuster",
        url: `${base}${route}`,
        severity: sensitive ? "high" : "low",
        title: sensitive
          ? `Erişilebilir yönetim yolu: ${route} (HTTP ${status})`
          : `Erişilebilir yol: ${route} (HTTP ${status})`,
        description: `${base}${route} yolu HTTP ${status} döndürüyor.` +
          (sensitive ? " Yol adı bir yönetim/giriş paneline işaret ediyor." : ""),
        fixKey: sensitive ? "admin_panel" : null
      }));
    }

    return { issues, nextId: id };
  }

  async run(ctx, target, opts = {}) {
    const wordlist = this.resolveWordlist(opts.wordlist);
    if (!wordlist) {
      console.log("\x1b[33m  Gobuster için kelime listesi bulunamadı. " +
        "'dirb' veya 'seclists' kurun ya da opts.wordlist verin; bu araç atlanıyor.\x1b[0m");
      return [];
    }

    const outputFile = path.join(this.rootDir, "gobuster_output.txt");
    try { fs.rmSync(outputFile, { force: true }); } catch { /* yoksa sorun değil */ }

    await this.spawnTool(
      this.binary,
      ["dir", "-u", target, "-w", wordlist, "-q", "-o", outputFile],
      { title: `Gobuster: ${target} (wordlist: ${wordlist})` }
    );

    let text = "";
    try { text = fs.readFileSync(outputFile, "utf8"); } catch { /* boş */ }

    const { issues, nextId } = this.parse(text, ctx.nextId, target);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`\nToplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = GobusterAdapter;
