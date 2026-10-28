// src/safe/SafeSession.js
// Yetkili uzaktan yama oturumu.
// - Kimlik bilgisi YALNIZCA bellekte (_pass) tutulur; diske/log'a ASLA yazılmaz.
// - Her adım (kaynak + hedef komutları) zaman damgalı yerel log'a kaydedilir.
// - Çalıştırmadan önce plan gösterilir ve onay alınır; config değişmeden yedeklenir.
const fs = require("fs");
const path = require("path");
const { SEVERITY_ORDER } = require("../issue");
const { FIX_GUIDES } = require("../fixGuides");
const scanStore = require("../scanStore");
const transports = require("./transports");
const rs = require("../riskScorer");

// Zaman damgalı, çift taraflı denetim log'u. Kimlik bilgisi yazılmaz.
class AuditLogger {
  constructor(target) {
    this.lines = [];
    const safeName = String(target).replace(/^https?:\/\//i, "").replace(/[^\w.-]/g, "_");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    this.path = path.join(scanStore.REPORTS_DIR, `remediation-${safeName}-${stamp}.log`);
  }
  _write(tag, msg) {
    const line = `[${new Date().toISOString()}] [${tag}] ${msg}`;
    this.lines.push(line);
  }
  src(msg) { this._write("SRC", msg); }           // kaynak PC tarafı
  tgt(msg) { this._write("TGT", msg); }           // hedef cihaz tarafı
  flush() {
    try {
      if (!fs.existsSync(scanStore.REPORTS_DIR)) fs.mkdirSync(scanStore.REPORTS_DIR, { recursive: true });
      fs.writeFileSync(this.path, this.lines.join("\n") + "\n");
    } catch { /* log yazılamazsa sessizce geç */ }
  }
}

class SafeSession {
  constructor(target) {
    this.target = String(target || "").replace(/^https?:\/\//i, "").split("/")[0];
    this.transport = "ssh";     // varsayılan
    this.user = null;
    this._pass = null;          // yalnızca bellekte
    this.keyPath = null;
    this.port = null;           // transport varsayılanı kullanılır
    this.filePath = null;
    this.items = [];            // [{ n, issue }]  (severity sıralı, 1..n)
    this.selected = new Set();
  }

  // ───────── Tarama dosyası ─────────
  loadFile(filePath) {
    const data = scanStore.readScan(filePath);
    this.filePath = filePath;
    if (data.target) this.target = String(data.target).replace(/^https?:\/\//i, "").split("/")[0];

    const sorted = data.issues
      .slice()
      .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));

    this.items = sorted.map((issue, i) => ({ n: i + 1, issue }));
    this.selected = new Set();
    return this.items.length;
  }

  autoLoad() {
    const latest = scanStore.findLatestFor(this.target);
    if (latest) return this.loadFile(latest);
    return 0;
  }

  // ───────── Ayarlar ─────────
  setTransport(name) {
    const key = String(name || "").toLowerCase();
    if (!transports.available().includes(key)) {
      throw new Error(`Geçersiz bağlantı türü: ${name}. Seçenekler: ${transports.available().join(", ")}`);
    }
    this.transport = key;
  }

  setSelection(spec) {
    if (!this.items.length) throw new Error("Önce bir tarama dosyası yükleyin (set file <yol>).");
    if (/^all$/i.test(spec)) {
      this.selected = new Set(this.items.map(it => it.n));
      return;
    }
    const nums = spec.split(",").map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    const max = this.items.length;
    const invalid = nums.filter(n => n < 1 || n > max);
    if (invalid.length) throw new Error(`Geçersiz sıra numarası: ${invalid.join(", ")} (1-${max} arası)`);
    this.selected = new Set(nums);
  }

  selectedItems() {
    return this.items.filter(it => this.selected.has(it.n));
  }

  // ───────── Görünüm ─────────
  authState() {
    if (this.keyPath) return "(anahtar ayarlandı, bellekte)";
    if (this._pass) return "(parola ayarlandı, bellekte)";
    return "(ayarlanmadı)";
  }

  renderShow() {
    const L = [];
    L.push("");
    L.push("\x1b[36mSettings :\x1b[0m");
    L.push(`  transport : ${this.transport}`);
    L.push(`  target    : ${this.target}`);
    L.push(`  user      : ${this.user || "(ayarlanmadı)"}`);
    L.push(`  auth      : ${this.authState()}`);
    L.push(`  seçilen   : ${this.selected.size ? [...this.selected].sort((a, b) => a - b).join(",") : "(yok)"}  \x1b[90m(select ile değiştir)\x1b[0m`);
    L.push("");
    L.push("\x1b[90m-- Tarama Dosyası --\x1b[0m");
    L.push(`  ${this.filePath || "(yüklenmedi — set file <yol>)"}`);
    L.push("");
    L.push("\x1b[90m-- Kapatılacak Zafiyetler --\x1b[0m");
    if (!this.items.length) {
      L.push("  (tarama dosyası yok)");
    } else {
      for (const { n, issue } of this.items) {
        const sel = this.selected.has(n) ? "\x1b[32m*\x1b[0m" : " ";
        const loc = issue.port ? `${issue.port}/tcp` : (issue.url || issue.ip || issue.host || "");
        L.push(` ${sel}${String(n).padStart(2)}- [${issue.severity}] ${loc.padEnd(10)} ${issue.title}`);
      }
      L.push("\x1b[90m  (* = seçili)\x1b[0m");
    }
    L.push("");
    return L.join("\n");
  }

  // ───────── Plan ─────────
  planFor(issue) {
    const guide = issue.fixKey ? FIX_GUIDES[issue.fixKey] : null;
    const rem = guide && guide.remediate;
    if (!rem) {
      return { ok: false, reason: "Bu zafiyet türü için otomatik yama tanımlı değil (elle: fix rehberine bakın)." };
    }
    if (rem.os && rem.os !== "linux") {
      return { ok: false, reason: `Otomatik yama yalnızca ${rem.os} için tanımlı.` };
    }
    return { ok: true, remediate: rem };
  }

  // Paket yöneticisine göre yükseltme komutları (OS-duyarlı).
  buildPackageUpgrade(packages, pkgManager) {
    if (!packages || !packages.length) return [];
    const list = packages.join(" ");
    switch (pkgManager) {
      case "apt-get": return [`apt-get update`, `apt-get install --only-upgrade -y ${list}`];
      case "dnf": return [`dnf upgrade -y ${list}`];
      case "yum": return [`yum update -y ${list}`];
      case "apk": return [`apk upgrade ${list}`];
      case "zypper": return [`zypper --non-interactive update ${list}`];
      default: return null; // paket yöneticisi bilinmiyor
    }
  }

  // Bir zafiyet için çalıştırılacak komut setini üretir (yedek + uygula + doğrula).
  buildCommandSet(rem, osInfo) {
    const sudo = (rem.sudo && this.user !== "root") ? "sudo " : "";
    const backup = (rem.backup || []).map(f => `${sudo}cp -n ${f} ${f}.bak`);
    let apply = (rem.commands || []).map(c => `${sudo}${c}`);

    if (rem.packages && rem.packages.length) {
      const up = this.buildPackageUpgrade(rem.packages, osInfo && osInfo.pkgManager);
      if (up === null) {
        return { error: `Hedefin paket yöneticisi belirlenemedi; '${rem.packages.join(", ")}' yükseltilemiyor.` };
      }
      apply = apply.concat(up.map(c => `${sudo}${c}`));
    }

    const verify = (rem.verify || []).map(v => ({ command: v.command, pass: new RegExp(v.pass, "i") }));
    return { backup, apply, verify };
  }

  // Hedefin OS/paket yöneticisi/init sistemini tespit eder.
  async detectOS(t) {
    const out = { kernel: "", pkgManager: null, initSystem: "unknown" };
    try {
      const kernel = await t.exec("uname -s");
      out.kernel = (kernel.stdout || "").trim();
      const pm = await t.exec("for m in apt-get dnf yum apk zypper; do command -v $m >/dev/null 2>&1 && echo $m && break; done");
      out.pkgManager = ((pm.stdout || "").trim().split(/\s+/)[0]) || null;
      const init = await t.exec("ps -p 1 -o comm= 2>/dev/null");
      out.initSystem = /systemd/.test(init.stdout || "") ? "systemd" : ((init.stdout || "").trim() || "unknown");
    } catch { /* tespit başarısızsa varsayılanlar kalır */ }
    return out;
  }

  // Bağlanmadan planlanan komutları döndürür (run --dry).
  dryPlan() {
    return this.selectedItems().map(({ n, issue }) => {
      const p = this.planFor(issue);
      if (!p.ok) return { n, issue, skip: p.reason };
      const set = this.buildCommandSet(p.remediate, null);
      if (set.error) return { n, issue, skip: set.error };
      return { n, issue, commands: [...set.backup, ...set.apply] };
    });
  }

  // ───────── Çalıştır ─────────
  // askConfirmation: (soru) => Promise<cevap>
  async run(askConfirmation, { reboot = null, dry = false } = {}) {
    if (!this.items.length) throw new Error("Tarama dosyası yüklenmedi.");
    if (!this.selected.size) throw new Error("Hiç zafiyet seçilmedi (select <n,n> veya select all).");

    const chosen = this.selectedItems();
    const riskBefore = rs.computeScore(chosen.map(c => c.issue));

    // --dry: bağlanmadan planlanan komutları döndür
    if (dry) {
      return { dry: true, plan: this.dryPlan(), riskBefore };
    }

    if (this.transport !== "dryrun") {
      if (!this.user) throw new Error("Kullanıcı ayarlanmadı (set user <ad>).");
      if (!this._pass && !this.keyPath) throw new Error("Kimlik ayarlanmadı (set pass veya set key <yol>).");
    }

    const logger = new AuditLogger(this.target);
    logger.src(`safe oturumu başladı. hedef=${this.target} transport=${this.transport} user=${this.user || "-"} seçili=${[...this.selected].sort((a, b) => a - b).join(",")}`);

    // Plan özeti
    console.log(`\n\x1b[36m  ──── Yama Planı (${chosen.length} zafiyet) ────\x1b[0m`);
    chosen.forEach(({ n, issue }) => {
      const p = this.planFor(issue);
      const tag = p.ok ? "\x1b[32myamalanacak\x1b[0m" : "\x1b[33matlanacak\x1b[0m";
      console.log(`   ${n}- [${issue.severity}] ${issue.title}  → ${tag}`);
    });

    const t = this._transport || transports.create(this.transport);
    if (t.insecure) {
      console.log(`\n\x1b[31m  [!] UYARI: ${this.transport} kimlik bilgilerini DÜZ METİN gönderir. Yalnızca güvenli/yerel ağda kullanın.\x1b[0m`);
    }

    const ans = await askConfirmation(`\n  Bu zafiyetler ${this.target} üzerinde kapatılacak. Onaylıyor musunuz? (E/H): `);
    if (!/^(e|y)/i.test((ans || "").trim())) {
      console.log("\x1b[33m  İşlem iptal edildi.\x1b[0m");
      logger.src("kullanıcı onayı reddetti; işlem iptal.");
      logger.flush();
      return { cancelled: true, logPath: logger.path };
    }

    console.log(`\n\x1b[36m  [*] ${this.transport} ile ${this.target} bağlanılıyor...\x1b[0m`);
    logger.src(`bağlanılıyor (${this.transport})`);
    try {
      await t.connect({ host: this.target, port: this.port || undefined, user: this.user, password: this._pass, keyPath: this.keyPath });
    } catch (e) {
      console.log(`\x1b[31m  Bağlantı başarısız: ${e.message}\x1b[0m`);
      logger.src(`bağlantı başarısız: ${e.message}`);
      logger.flush();
      this.wipeCredentials();
      return { connectError: e.message, logPath: logger.path };
    }
    logger.src("bağlantı kuruldu");

    // OS tespiti (dryrun gerçek bağlanmadığı için geçişli varsayılan kullanır)
    this.osInfo = (t.name === "dryrun")
      ? { kernel: "Linux", pkgManager: "apt-get", initSystem: "unknown" }
      : await this.detectOS(t);
    logger.src(`os: kernel=${this.osInfo.kernel || "?"} pkg=${this.osInfo.pkgManager || "?"} init=${this.osInfo.initSystem}`);

    const applied = [];
    const skipped = [];
    const failed = [];

    for (const { n, issue } of chosen) {
      const plan = this.planFor(issue);
      if (!plan.ok) {
        skipped.push({ n, issue, reason: plan.reason });
        logger.src(`#${n} atlandı: ${plan.reason}`);
        continue;
      }
      const rem = plan.remediate;

      // systemd gerektiren yama, systemd olmayan hedefte uygulanamaz
      if (rem.needs === "systemd" && this.osInfo.initSystem && !["systemd", "unknown"].includes(this.osInfo.initSystem)) {
        failed.push({ n, issue, reason: `Hedefte systemd yok (init=${this.osInfo.initSystem}); otomatik yama uygulanamadı.` });
        logger.src(`#${n} kapatılamadı: systemd yok`);
        continue;
      }

      const set = this.buildCommandSet(rem, this.osInfo);
      if (set.error) {
        failed.push({ n, issue, reason: set.error });
        logger.src(`#${n} kapatılamadı: ${set.error}`);
        continue;
      }

      let failReason = null;
      try {
        for (const cmd of set.backup) {
          logger.tgt(`[yedek] ${cmd}`);
          const r = await t.exec(cmd);
          logger.tgt(`[yedek] exit=${r.code}`);
        }
        for (const cmd of set.apply) {
          logger.tgt(`[yama] ${cmd}`);
          const r = await t.exec(cmd);
          logger.tgt(`[yama] exit=${r.code}${r.stderr ? " err=" + r.stderr.trim().slice(0, 200) : ""}`);
          if (r.code !== 0) {
            failReason = /sudo|permission|denied|not permitted|yetki/i.test(r.stderr || "")
              ? "Hedefte yeterli yetki yok (sudo/izin başarısız)."
              : `Komut hata verdi (exit ${r.code}).`;
            break;
          }
        }
      } catch (e) {
        failReason = e.message;
      }

      if (failReason) {
        failed.push({ n, issue, reason: failReason });
        logger.src(`#${n} kapatılamadı: ${failReason}`);
        continue;
      }

      // Yama sonrası doğrulama
      let verified = null; // null = doğrulama tanımsız
      if (set.verify.length) {
        verified = true;
        for (const v of set.verify) {
          logger.tgt(`[doğrula] ${v.command}`);
          const r = await t.exec(v.command);
          const ok = v.pass.test(r.stdout || "");
          logger.tgt(`[doğrula] ${ok ? "geçti" : "GEÇMEDİ"} (exit=${r.code})`);
          if (!ok) { verified = false; break; }
        }
      }
      applied.push({ n, issue, verified });
      logger.src(`#${n} yamalandı${verified === false ? " (DOĞRULANAMADI)" : verified === true ? " (doğrulandı)" : ""}: ${issue.title}`);
    }

    // Reboot (opsiyonel, ayrı onay)
    let rebooted = false;
    if (applied.length > 0) {
      let doReboot = reboot;
      if (doReboot === null) {
        const rb = await askConfirmation("\n  Değişikliklerin tamamı için makineye reboot atılsın mı? (E/H): ");
        doReboot = /^(e|y)/i.test((rb || "").trim());
      }
      if (doReboot) {
        const sudo = this.user !== "root" ? "sudo " : "";
        logger.tgt(`[reboot] ${sudo}reboot`);
        try { await t.exec(`${sudo}reboot`); } catch { /* bağlantı kopabilir, normal */ }
        rebooted = true;
        logger.src("reboot komutu gönderildi");
      }
    }

    try { await t.disconnect(); } catch { /* yok say */ }
    logger.src("bağlantı kapatıldı");
    this.wipeCredentials();
    logger.src("kimlik bilgisi bellekten silindi");

    // Önce/sonra risk: doğrulanarak (veya doğrulamasız) kapatılanlar düşülür; verify başarısızsa açık sayılır
    const closed = applied.filter(a => a.verified !== false).map(a => a.issue);
    const stillOpen = chosen.map(c => c.issue).filter(i => !closed.includes(i));
    const riskAfter = rs.computeScore(stillOpen);
    logger.src(`risk: önce=${riskBefore} sonra=${riskAfter}`);
    logger.flush();

    return {
      applied, skipped, failed, rebooted,
      riskBefore, riskAfter,
      logPath: logger.path,
      dryCommands: t.name === "dryrun" ? t.commands : null
    };
  }

  // Bir remediation log'undaki config yedeklerinden (.bak) geri yükler.
  async rollback(logPath, askConfirmation) {
    if (!fs.existsSync(logPath)) throw new Error(`Log dosyası bulunamadı: ${logPath}`);
    const text = fs.readFileSync(logPath, "utf8");

    const files = [];
    const re = /cp -n (\S+) \S+\.bak/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!files.includes(m[1])) files.push(m[1]);
    }
    if (!files.length) return { none: true };

    if (this.transport !== "dryrun") {
      if (!this.user) throw new Error("Kullanıcı ayarlanmadı (set user <ad>).");
      if (!this._pass && !this.keyPath) throw new Error("Kimlik ayarlanmadı (set pass veya set key <yol>).");
    }

    console.log("\n\x1b[33m  Geri yüklenecek yedekler:\x1b[0m");
    files.forEach(f => console.log(`   ${f}.bak → ${f}`));
    const ans = await askConfirmation(`\n  ${this.target} üzerinde bu yedekler geri yüklensin mi? (E/H): `);
    if (!/^(e|y)/i.test((ans || "").trim())) {
      console.log("\x1b[33m  İptal edildi.\x1b[0m");
      return { cancelled: true };
    }

    const logger = new AuditLogger(this.target);
    logger.src(`rollback başladı. kaynak=${logPath} dosyalar=${files.join(", ")}`);
    const t = this._transport || transports.create(this.transport);
    try {
      await t.connect({ host: this.target, port: this.port || undefined, user: this.user, password: this._pass, keyPath: this.keyPath });
    } catch (e) {
      logger.src(`bağlantı başarısız: ${e.message}`);
      logger.flush();
      this.wipeCredentials();
      return { connectError: e.message, logPath: logger.path };
    }

    const sudo = this.user !== "root" ? "sudo " : "";
    const restored = [];
    const failedR = [];
    for (const f of files) {
      const cmd = `${sudo}cp ${f}.bak ${f}`;
      logger.tgt(`[rollback] ${cmd}`);
      try {
        const r = await t.exec(cmd);
        logger.tgt(`[rollback] exit=${r.code}`);
        if (r.code === 0) restored.push(f);
        else failedR.push({ f, reason: `exit ${r.code}` });
      } catch (e) {
        failedR.push({ f, reason: e.message });
      }
    }

    try { await t.disconnect(); } catch { /* yok say */ }
    this.wipeCredentials();
    logger.src(`rollback bitti. geri yüklenen=${restored.length}, başarısız=${failedR.length}`);
    logger.flush();

    return { restored, failed: failedR, logPath: logger.path, dryCommands: t.name === "dryrun" ? t.commands : null };
  }

  wipeCredentials() {
    this._pass = null;
    // keyPath bir dosya yolu (sır değil) ama oturumu temiz bırakalım
  }
}

module.exports = { SafeSession };
