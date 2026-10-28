// src/tools/adapters/zap.js
const fs = require("fs");
const path = require("path");
const { Adapter } = require("../Adapter");
const { parseZapFile } = require("../../parsers/zap");

class ZapAdapter extends Adapter {
  constructor() {
    const binary = process.platform === "win32" ? "zap.bat" : "zap.sh";
    super({
      name: "zap",
      label: "OWASP ZAP",
      category: "web",
      binary,
      versionCmd: `${binary} -version`,
      aptPackage: "zaproxy",
      installUrl: "https://www.zaproxy.org/download/",
      mode: "managed",
      targetTypes: ["url"]
    });
  }

  /**
   * @param ctx    XasContext
   * @param target taranacak URL
   * @param opts   { full?: boolean }  (ZAP quick scan her iki modda da aynıdır)
   */
  async run(ctx, target) {
    const url = Array.isArray(target) ? target[0] : target;
    const outputFile = path.join(this.rootDir, "zap_output.json");

    // Eski çıktıyı sil ki araç başarısız olursa bayat sonuç yeniden parse edilmesin.
    try { fs.rmSync(outputFile, { force: true }); } catch { /* yoksa sorun değil */ }

    console.log(`\n--- ZAP Taraması Başlıyor: ${url} ---\n`);

    await this.spawnTool(this.binary, ["-cmd", "-quickurl", url, "-quickout", outputFile]);

    if (!fs.existsSync(outputFile)) {
      console.log("\x1b[33m  ZAP çıktı dosyası oluşmadı (tarama başarısız). Atlanıyor.\x1b[0m");
      return [];
    }

    console.log("\n--- ZAP Bitti, Çıktı Parse Ediliyor ---\n");

    try {
      const { issues, nextId } = parseZapFile(outputFile, ctx.nextId);
      ctx.issues.push(...issues);
      ctx.nextId = nextId;
      console.log(`Toplam ${issues.length} yeni zafiyet eklendi.`);
      return issues;
    } catch (e) {
      console.log("Parse hatası:", e.message);
      return [];
    }
  }
}

module.exports = ZapAdapter;
