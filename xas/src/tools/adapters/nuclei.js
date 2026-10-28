// src/tools/adapters/nuclei.js
// Şablon tabanlı zafiyet tarayıcısı. JSONL çıktısını ayrıştırır.
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

// Bulgu adı/etiketlerinden fix rehberi anahtarı.
const KEYWORD_FIX = [
  [/sqli|sql-injection|sql injection/i, "sql_injection"],
  [/\bxss\b|cross-site-scripting/i, "xss"],
  [/\bcsrf\b/i, "csrf"],
  [/\bcors\b/i, "cors_misconfig"],
  [/open-redirect|open redirect/i, "open_redirect"],
  [/directory-listing|directory listing|dir-listing/i, "directory_listing"],
  [/default-login|admin-panel|admin panel|default-credential/i, "admin_panel"],
  [/\btls\b|\bssl\b|certificate/i, "ssl_expired"],
  [/security-header|missing-header|x-frame|csp/i, "missing_headers"]
];

const VALID_SEV = new Set(["critical", "high", "medium", "low", "info"]);

class NucleiAdapter extends Adapter {
  constructor() {
    super({
      name: "nuclei",
      label: "Nuclei",
      category: "web",
      binary: "nuclei",
      versionCmd: "nuclei -version",
      aptPackage: null, // genelde go/installer ile kurulur
      installUrl: "https://github.com/projectdiscovery/nuclei",
      mode: "managed",
      targetTypes: ["url"]
    });
  }

  classify(text) {
    for (const [re, fixKey] of KEYWORD_FIX) {
      if (re.test(text)) return fixKey;
    }
    return null;
  }

  // nuclei JSONL çıktısını ayrıştırır (her satır bir JSON bulgu).
  parse(text, startId) {
    const issues = [];
    let id = startId;

    for (const raw of String(text).split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line[0] !== "{") continue;

      let obj;
      try { obj = JSON.parse(line); } catch { continue; }

      const info = obj.info || {};
      const sev = VALID_SEV.has((info.severity || "").toLowerCase()) ? info.severity.toLowerCase() : "info";
      const name = info.name || obj["template-id"] || "Nuclei bulgusu";
      const tags = Array.isArray(info.tags) ? info.tags.join(" ") : (info.tags || "");
      const where = obj["matched-at"] || obj.matched || obj.host || "";
      const cveList = info.classification && info.classification["cve-id"];
      const cve = Array.isArray(cveList) && cveList.length ? cveList.join(", ") : null;

      issues.push(new Issue({
        id: id++,
        source: "nuclei",
        url: where,
        severity: sev,
        title: name,
        description: `${obj["template-id"] || ""} → ${where}`.trim(),
        fixKey: this.classify(`${name} ${tags}`),
        cve
      }));
    }

    return { issues, nextId: id };
  }

  async run(ctx, target) {
    const { output } = await this.spawnTool(
      this.binary,
      ["-u", target, "-jsonl", "-silent"],
      { title: `Nuclei: ${target}`, capture: true }
    );

    const { issues, nextId } = this.parse(output, ctx.nextId);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`\nToplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = NucleiAdapter;
