// src/tools/Adapter.js
// Tüm güvenlik araçları için ortak taban sınıf (adapter arayüzü).
// Her araç bu sınıfı genişletir ve kendi run() / parse() mantığını uygular.

const { execSync, spawn } = require("child_process");
const path = require("path");

class Adapter {
  /**
   * @param {object} o
   * @param {string}   o.name         Benzersiz kısa ad (ör. "nmap")
   * @param {string}   [o.label]      Görünen ad (ör. "Nmap")
   * @param {string}   o.category     recon | web | traffic | exploit
   * @param {string}   o.binary       Çalıştırılabilir dosya adı
   * @param {string}   [o.versionCmd] Kurulu mu kontrolü için komut
   * @param {string}   [o.aptPackage] Linux apt paket adı
   * @param {string}   [o.installUrl] apt yoksa / Windows için indirme bağlantısı
   * @param {string}   [o.mode]       "managed" (çıktı ayrıştırılır) | "launch" (sadece başlatılır)
   * @param {string[]} [o.targetTypes] ["ip","url"] gibi; hangi hedeflere uygulanır
   * @param {string}   [o.launchCmd]  launch modunda çalıştırılacak komut
   */
  constructor(o) {
    this.name = o.name;
    this.label = o.label || o.name;
    this.category = o.category;
    this.binary = o.binary;
    this.versionCmd = o.versionCmd || `${o.binary} --version`;
    this.aptPackage = o.aptPackage || null;
    this.installUrl = o.installUrl || null;
    this.mode = o.mode || "managed";
    this.targetTypes = o.targetTypes || ["ip", "url"];
    this.launchCmd = o.launchCmd || o.binary;

    // Proje kök dizini (xas/). Adapter.js => src/tools, iki üst => xas/.
    this.rootDir = path.resolve(__dirname, "..", "..");
  }

  // ───────── Kurulum durumu ─────────
  // Önce PATH'te binary var mı diye bakar (bazı araçların --version'ı 0 dönmez),
  // olmazsa versionCmd'yi dener.
  isInstalled() {
    const probe = process.platform === "win32"
      ? `where ${this.binary}`
      : `command -v ${this.binary}`;
    try {
      execSync(probe, { stdio: "pipe" });
      return true;
    } catch {
      /* PATH'te bulunamadı; versionCmd'yi dene */
    }
    try {
      execSync(this.versionCmd, { stdio: "pipe" });
      return true;
    } catch {
      return false;
    }
  }

  appliesTo(type) {
    return this.targetTypes.includes(type);
  }

  // ───────── Kurulum (onaylı) ─────────
  // askConfirmation: (soru) => Promise<cevap>
  async install(askConfirmation) {
    if (process.platform !== "linux") {
      return {
        success: false,
        manual: true,
        message: `Otomatik kurulum yalnızca Linux'ta desteklenir. İndir: ${this.installUrl || "kaynak tanımlı değil"}`
      };
    }
    if (!this.aptPackage) {
      return {
        success: false,
        manual: true,
        message: `apt paketi tanımlı değil. Kaynak: ${this.installUrl || "-"}`
      };
    }

    const ans = await askConfirmation(
      `  ${this.label} kurulu değil. 'sudo apt install -y ${this.aptPackage}' çalıştırılsın mı? (E/H): `
    );
    if (!/^(e|y)/i.test((ans || "").trim())) {
      return { success: false, cancelled: true };
    }

    try {
      const output = execSync(`sudo apt install -y ${this.aptPackage}`, {
        encoding: "utf8",
        stdio: "pipe"
      });
      return { success: true, output };
    } catch (e) {
      return { success: false, error: e.message || e.stderr || "kurulum hatası" };
    }
  }

  // ───────── Ortak çalıştırıcı ─────────
  // Aracı spawn eder, kapanınca { code, output } döner.
  //   capture:true → stdout/stderr biriktirilip output olarak döner
  //   quiet:true   → çıktı ekrana basılmaz (ör. ikincil analiz çağrıları)
  spawnTool(command, args, { title, capture = false, quiet = false } = {}) {
    return new Promise(resolve => {
      if (title) console.log(`\n--- ${title} ---\n`);

      let proc;
      try {
        proc = spawn(command, args);
      } catch (e) {
        console.log(`\x1b[31m  ${command} başlatılamadı: ${e.message}\x1b[0m`);
        return resolve({ error: e, output: "" });
      }

      let out = "";
      const sink = d => {
        const s = d.toString();
        if (!quiet) process.stdout.write(s);
        if (capture) out += s;
      };

      proc.stdout.on("data", sink);
      proc.stderr.on("data", sink);
      proc.on("error", e => {
        console.log(`\x1b[31m  ${command} hatası: ${e.message}\x1b[0m`);
      });
      proc.on("close", code => resolve({ code, output: out }));
    });
  }

  // ───────── Alt sınıfların uygulaması ─────────
  // managed adapter'lar override eder: tarar, parse eder, ctx.issues'a ekler, eklenen Issue[] döner.
  async run() {
    throw new Error(`${this.name}: run() uygulanmadı`);
  }

  // launch adapter'lar: GUI aracı ayrı pencerede, arka planda başlatır.
  launch(args = []) {
    try {
      const child = spawn(this.launchCmd, args, { detached: true, stdio: "ignore" });
      // Binary bulunamazsa 'error' asenkron gelir; dinleyici yoksa süreç çöker.
      child.on("error", () => { /* isInstalled() çağrı öncesi kontrol eder */ });
      child.unref();
      return { success: true };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
}

module.exports = { Adapter };
