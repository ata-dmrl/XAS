// src/tools/adapters/sqlmap.js
// SQL injection tarayıcısı. --batch ile etkileşimsiz çalışır, stdout'tan sonucu ayrıştırır.
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

class SqlmapAdapter extends Adapter {
  constructor() {
    super({
      name: "sqlmap",
      label: "sqlmap",
      category: "web",
      binary: "sqlmap",
      versionCmd: "sqlmap --version",
      aptPackage: "sqlmap",
      installUrl: "https://sqlmap.org/",
      mode: "managed",
      targetTypes: ["url"]
    });
  }

  // sqlmap stdout'unu ayrıştırır. Zafiyet varsa her enjekte edilebilir parametre için bir Issue üretir.
  parse(output, startId, target) {
    const issues = [];
    let id = startId;
    const text = String(output);

    const vulnerable = /sqlmap identified the following injection point|is vulnerable/i.test(text);
    if (!vulnerable) return { issues, nextId: id };

    // "Parameter: id (GET)" gibi satırları yakala
    const params = [];
    const re = /Parameter:\s*([^\n(]+?)\s*\(([^)]+)\)/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      params.push({ name: m[1].trim(), where: m[2].trim() });
    }
    if (params.length === 0) params.push({ name: "bilinmeyen parametre", where: "" });

    for (const p of params) {
      issues.push(new Issue({
        id: id++,
        source: "sqlmap",
        url: target || "",
        severity: "critical",
        title: `SQL Injection: ${p.name}${p.where ? ` (${p.where})` : ""}`,
        description: `sqlmap, ${target || "hedef"} üzerinde '${p.name}' parametresinin SQL injection'a açık olduğunu doğruladı.`,
        fixKey: "sql_injection",
        confidence: "yüksek"
      }));
    }

    return { issues, nextId: id };
  }

  async run(ctx, target) {
    const { output } = await this.spawnTool(
      this.binary,
      ["-u", target, "--batch", "--flush-session", "--disable-coloring"],
      { title: `sqlmap: ${target}`, capture: true }
    );

    const { issues, nextId } = this.parse(output, ctx.nextId, target);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`\nToplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = SqlmapAdapter;
