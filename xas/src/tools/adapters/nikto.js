// src/tools/adapters/nikto.js
// Web sunucu zafiyet tarayıcısı. CSV çıktısını ayrıştırır.
const fs = require("fs");
const path = require("path");
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

// Bulgu metnindeki anahtar kelimeye göre fix rehberi anahtarı.
const KEYWORD_FIX = [
  [/x-frame-options|x-content-type|content-security|clickjacking|header/i, "missing_headers", "medium"],
  [/index of|directory indexing|directory listing/i, "directory_listing", "medium"],
  [/cookie|httponly|secure flag/i, "missing_headers", "low"],
  [/ssl|tls|certificate/i, "ssl_expired", "medium"],
  [/cors|access-control-allow-origin/i, "cors_misconfig", "medium"]
];

class NiktoAdapter extends Adapter {
  constructor() {
    super({
      name: "nikto",
      label: "Nikto",
      category: "web",
      binary: "nikto",
      versionCmd: "nikto -Version",
      aptPackage: "nikto",
      installUrl: "https://github.com/sullo/nikto",
      mode: "managed",
      targetTypes: ["url"]
    });
  }

  classify(message) {
    for (const [re, fixKey, sev] of KEYWORD_FIX) {
      if (re.test(message)) return { fixKey, severity: sev };
    }
    return { fixKey: null, severity: "medium" };
  }

  // Nikto CSV çıktısını ayrıştırır. Her satır tırnaklı alanlardan oluşur:
  // "host","ip","port","osvdb","method","uri","message"
  parse(csv, startId) {
    const issues = [];
    let id = startId;

    for (const raw of String(csv).split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;

      const fields = (line.match(/"([^"]*)"/g) || []).map(s => s.slice(1, -1));
      if (fields.length < 7) continue;

      const [host, ip, port, , method, uri, message] = fields;
      if (!message) continue;

      const { fixKey, severity } = this.classify(message);
      const base = host ? `${host}${port && port !== "80" ? ":" + port : ""}` : ip;

      issues.push(new Issue({
        id: id++,
        source: "nikto",
        host,
        ip,
        port: port ? Number(port) : null,
        url: `${base}${uri || ""}`,
        severity,
        title: message.length > 90 ? message.slice(0, 87) + "..." : message,
        description: `${method ? method + " " : ""}${uri || "/"} → ${message}`,
        fixKey
      }));
    }

    return { issues, nextId: id };
  }

  async run(ctx, target) {
    const outputFile = path.join(this.rootDir, "nikto_output.csv");
    try { fs.rmSync(outputFile, { force: true }); } catch { /* yoksa sorun değil */ }

    await this.spawnTool(
      this.binary,
      ["-h", target, "-Format", "csv", "-output", outputFile, "-nointeractive"],
      { title: `Nikto: ${target}` }
    );

    let csv = "";
    try {
      csv = fs.readFileSync(outputFile, "utf8");
    } catch {
      console.log("\x1b[33m  Nikto çıktı dosyası okunamadı (tarama başarısız olmuş olabilir).\x1b[0m");
    }

    const { issues, nextId } = this.parse(csv, ctx.nextId);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`\nToplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = NiktoAdapter;
