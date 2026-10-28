// src/tools/adapters/nmap.js
const fs = require("fs");
const path = require("path");
const { Adapter } = require("../Adapter");
const { parseNmapFile } = require("../../parsers/nmap");

class NmapAdapter extends Adapter {
  constructor() {
    super({
      name: "nmap",
      label: "Nmap",
      category: "recon",
      binary: "nmap",
      versionCmd: "nmap --version",
      aptPackage: "nmap",
      installUrl: "https://nmap.org/download.html",
      mode: "managed",
      targetTypes: ["ip", "url"]
    });
  }

  defaultArgs(target) {
    return ["-sV", target];
  }

  fullArgs(target) {
    return ["-sV", "-sC", "-A", "-O", "-p-", "-T4", target];
  }

  /**
   * @param ctx    XasContext
   * @param target hedef (opts.args verildiyse yok sayılır)
   * @param opts   { args?: string[], full?: boolean }
   */
  async run(ctx, target, opts = {}) {
    const outputFile = path.join(this.rootDir, "nmap_output.xml");
    const args = opts.args
      ? opts.args
      : (opts.full ? this.fullArgs(target) : this.defaultArgs(target));

    // Eski çıktıyı sil ki araç başarısız olursa bayat sonuç yeniden parse edilmesin.
    try { fs.rmSync(outputFile, { force: true }); } catch { /* yoksa sorun değil */ }

    await this.spawnTool(this.binary, [...args, "-oX", outputFile], {
      title: "Nmap Çalışıyor (Canlı Çıktı)"
    });

    if (!fs.existsSync(outputFile)) {
      console.log("\x1b[33m  Nmap çıktı dosyası oluşmadı (tarama başarısız). Atlanıyor.\x1b[0m");
      return [];
    }

    console.log("\n--- Nmap Bitti, Çıktı Parse Ediliyor ---\n");

    try {
      const { issues, nextId } = await parseNmapFile(outputFile, ctx.nextId);
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

module.exports = NmapAdapter;
