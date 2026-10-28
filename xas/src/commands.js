const { color, colorSeverity, SEVERITY_ORDER } = require("./issue");
const { FIX_GUIDES } = require("./fixGuides");
const { parseNmapFile } = require("./parsers/nmap");
const { parseZapFile } = require("./parsers/zap");
const registry = require("./tools/registry");
const riskScorer = require("./riskScorer");
const scanStore = require("./scanStore");
const scope = require("./scope");
const { SafeSession } = require("./safe/SafeSession");
const { generateTxtReport, generateHtmlReport, generateJsonReport } = require("./reportGenerator");
const { applyAutoFix } = require("./autoFixer");
const fs = require("fs");
const path = require("path");
const net = require("net");
const readline = require("readline");

class XasContext {
  constructor() {
    this.issues = [];
    this.nextId = 1;
    this.mode = "normal";   // "normal" | "scan" | "safe"
    this.safe = null;       // aktif SafeSession (safe kipinde)
  }
}

function isIP(str) {
  return net.isIP(str) !== 0;
}

function isURL(str) {
  return str.startsWith("http://") || str.startsWith("https://") || str.includes(".");
}

function printFixGuide(fixKey) {
  const guide = FIX_GUIDES[fixKey];
  if (!guide) {
    console.log("\x1b[31m  Bu zafiyet türü için henüz fix rehberi tanımlanmamış.\x1b[0m");
    return;
  }

  console.log(`\x1b[35m\n╔══════════════════════════════════════════════════╗\x1b[0m`);
  console.log(`\x1b[35m║\x1b[0m  \x1b[1m[${guide.severity.toUpperCase()}] ${guide.title}\x1b[0m`);
  console.log(`\x1b[35m╚══════════════════════════════════════════════════╝\x1b[0m`);

  guide.steps.forEach((step, index) => {
    console.log(`\n  \x1b[32m[${index + 1}] ${step.title}\x1b[0m`);
    (step.items || []).forEach(item => {
      console.log(`     \x1b[36m→\x1b[0m ${item}`);
    });
  });

  console.log(`\n  \x1b[33m💡 Öneri:\x1b[0m`);
  console.log(`     ${guide.recommendation}\n`);

  if (guide.autoFix) {
    console.log(`  \x1b[35m[!] Bu zafiyet için OTOMATİK DÜZELTME (Auto-Fix) mevcuttur.\x1b[0m`);
    console.log(`      Otomatik kapatmak için \x1b[36mfix auto <id>\x1b[0m komutunu kullanabilirsiniz.\n`);
  }
}

function askConfirmation(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }));
}

// Parola gibi gizli girdiler için: soruyu gösterir ama yazılanları ekrana basmaz.
function askHidden(query) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let muted = false;
    rl._writeToOutput = function (str) { if (!muted) rl.output.write(str); };
    rl.question(query, ans => {
      rl.close();
      rl.output.write("\n");
      resolve(ans);
    });
    muted = true;
  });
}

const CATEGORY_LABELS = {
  recon: "KEŞİF",
  web: "WEB UYGULAMASI",
  traffic: "AĞ TRAFİĞİ",
  exploit: "DOĞRULAMA / SÖMÜRÜ"
};
const CATEGORY_ORDER = ["recon", "web", "traffic", "exploit"];

function printTools() {
  console.log(`\n\x1b[36m  ──── Araç Durumu ────\x1b[0m`);

  for (const cat of CATEGORY_ORDER) {
    const list = registry.byCategory(cat);
    if (list.length === 0) continue;

    console.log(`\n  \x1b[33m${CATEGORY_LABELS[cat] || cat.toUpperCase()}\x1b[0m`);
    list.forEach(a => {
      const ok = a.isInstalled();
      const mark = ok ? "\x1b[32m✔\x1b[0m" : "\x1b[31m✘\x1b[0m";
      const modeTag = a.mode === "launch" ? "\x1b[90m[GUI]\x1b[0m " : "";
      let line = `    ${mark} ${a.name.padEnd(10)} ${modeTag}\x1b[90m${a.label}\x1b[0m`;
      if (!ok) line += `  \x1b[36m→ install ${a.name}\x1b[0m`;
      console.log(line);
    });
  }

  console.log("\n  \x1b[90mEksik araçları kurmak için: install <araç>\x1b[0m\n");
}

const GRADE_COLORS = { A: "\x1b[32m", B: "\x1b[36m", C: "\x1b[33m", D: "\x1b[31m", F: "\x1b[35m" };

function printRiskCard(target, issues) {
  const s = riskScorer.summarize(issues);
  const gc = GRADE_COLORS[s.grade.letter] || "\x1b[37m";
  const scoreLine = `RİSK SKORU: ${s.score.toFixed(1)} / 10   [${s.grade.letter} - ${s.grade.label}]`;

  console.log(`\n\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m`);
  console.log(`\x1b[36m║\x1b[0m  \x1b[1mXAS RİSK RAPORU — ${target}\x1b[0m`);
  console.log(`\x1b[36m╠══════════════════════════════════════════════════════╣\x1b[0m`);
  console.log(`\x1b[36m║\x1b[0m  ${gc}\x1b[1m${scoreLine}\x1b[0m`);
  console.log(`\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m`);

  const c = s.counts;
  console.log(
    `\n  Dağılım:  ${colorSeverity("critical", "CRITICAL " + c.critical)} │ ` +
    `${colorSeverity("high", "HIGH " + c.high)} │ ` +
    `${colorSeverity("medium", "MEDIUM " + c.medium)} │ ` +
    `${colorSeverity("low", "LOW " + c.low)} │ ` +
    `${colorSeverity("info", "INFO " + c.info)}`
  );

  if (s.top.length > 0) {
    console.log(`\n  \x1b[37mEn kritik bulgular:\x1b[0m`);
    s.top.forEach(i => {
      const sev = colorSeverity(i.severity, `[${i.severity.toUpperCase().padEnd(8)}]`);
      const loc = i.url || `${i.ip || i.host}${i.port ? ":" + i.port : ""}`;
      console.log(`   \x1b[37m#${i.id}\x1b[0m ${sev} ${i.title}  \x1b[90m${loc}\x1b[0m`);
    });
  }

  console.log(`\n  \x1b[36mKapatma rehberi:\x1b[0m guide   \x1b[90m|\x1b[0m  \x1b[36mtüm liste:\x1b[0m list   \x1b[90m|\x1b[0m  \x1b[36mrapor:\x1b[0m report\n`);
}

// Hedef yetkili kapsamda mı? Değilse false döner ve işlemi durdurur.
function enforceScope(target, action = "işlem") {
  const r = scope.isAllowed(target);
  if (r.empty) {
    console.log(`\x1b[90m  [scope] Kapsam tanımlı değil — tüm hedeflere izin var. Kısıtlamak için: scope add <ip/cidr/domain>\x1b[0m`);
    return true;
  }
  if (!r.allowed) {
    console.log(`\x1b[31m  [scope] REDDEDİLDİ: '${target}' yetkili kapsamda değil; ${action} yapılmadı.\x1b[0m`);
    console.log(`\x1b[90m  Eklemek için: scope add <ip/cidr/domain>  |  Görmek için: scope\x1b[0m`);
    return false;
  }
  console.log(`\x1b[90m  [scope] '${target}' yetkili (${r.matched}).\x1b[0m`);
  return true;
}

async function safeApply(ctx, opts = {}) {
  if (!opts.dry && !enforceScope(ctx.safe.target, "yama")) return;
  try {
    const res = await ctx.safe.run(askConfirmation, opts);
    printSafeResult(res);
  } catch (e) {
    console.log(`\x1b[31m  ${e.message}\x1b[0m`);
  }
}

function printSafeResult(res) {
  if (res.cancelled) return;

  if (res.dry) {
    console.log(`\n\x1b[36m  ──── Planlanan Komutlar (dry-run, bağlanılmadı) ────\x1b[0m`);
    res.plan.forEach(p => {
      if (p.skip) {
        console.log(`   ${p.n}- [${p.issue.severity}] ${p.issue.title}  → \x1b[33matlanır: ${p.skip}\x1b[0m`);
        return;
      }
      console.log(`   ${p.n}- [${p.issue.severity}] ${p.issue.title}`);
      p.commands.forEach(c => console.log(`        \x1b[90m$ ${c}\x1b[0m`));
    });
    console.log(`\n  \x1b[90mMevcut risk: ${res.riskBefore.toFixed(1)}/10 — gerçek uygulama için 'run'.\x1b[0m\n`);
    return;
  }

  if (res.connectError) {
    console.log(`\x1b[31m  Bağlantı hatası: ${res.connectError}\x1b[0m`);
    console.log(`\x1b[90m  Denetim log'u: ${res.logPath}\x1b[0m\n`);
    return;
  }

  console.log(`\n\x1b[32m  -- Kapatıldı (${res.applied.length}) --\x1b[0m`);
  res.applied.forEach(({ n, issue, verified }) => {
    const v = verified === true ? " \x1b[32m(doğrulandı)\x1b[0m"
      : verified === false ? " \x1b[31m(DOĞRULANAMADI — elle kontrol edin)\x1b[0m"
      : "";
    console.log(`   ${n}- [${issue.severity}] ${issue.title}${v}`);
  });

  if (res.skipped.length) {
    console.log(`\n\x1b[33m  -- Atlandı (${res.skipped.length}) --\x1b[0m`);
    res.skipped.forEach(({ n, issue, reason }) => {
      console.log(`   ${n}- [${issue.severity}] ${issue.title}`);
      console.log(`      \x1b[90m${reason}\x1b[0m`);
    });
  }

  if (res.failed.length) {
    console.log(`\n\x1b[31m  -- Kapatılamadı (${res.failed.length}) --\x1b[0m`);
    res.failed.forEach(({ n, issue, reason }) => {
      console.log(`   ${n}- [${issue.severity}] ${issue.title}`);
      console.log(`      \x1b[90m// ${reason}\x1b[0m`);
    });
  }

  if (res.rebooted) console.log(`\n\x1b[36m  [*] Reboot komutu gönderildi.\x1b[0m`);

  if (typeof res.riskBefore === "number") {
    console.log(`\n  \x1b[36mRisk (önce → sonra):\x1b[0m ${res.riskBefore.toFixed(1)} → ${res.riskAfter.toFixed(1)} / 10`);
  }

  if (res.dryCommands) {
    console.log(`\n\x1b[90m  [dryrun transport] çalıştırılan komutlar:\x1b[0m`);
    res.dryCommands.forEach(c => console.log(`   ${c}`));
  }

  console.log(`\n\x1b[90m  Denetim log'u: ${res.logPath}\x1b[0m\n`);
}

function printHelp() {
  console.log(`
\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m
\x1b[36m║\x1b[0m              \x1b[1mXAS Komut Rehberi\x1b[0m                       \x1b[36m║\x1b[0m
\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m

  \x1b[33m─── GENEL ───\x1b[0m
  help                           Yardım menüsü
  tools                          Araç durumu (tümü, kategorili)
  install <araç>                 Eksik aracı kur (onaylı, Linux/apt)
  launch <araç>                  GUI aracı başlat (Wireshark/Burp/Armitage)
  scope                          Yetkili hedef kapsamını göster/düzenle
  clear                          Ekranı temizle
  exit                           Çıkış

  \x1b[90m  scope add <ip/cidr/domain> · scope remove <e> · scope clear
  (kapsam tanımlıysa yalnızca listedeki hedeflere tarama/yama yapılır)\x1b[0m

  \x1b[33m─── TAM TARAMA ───\x1b[0m
  start <ip/domain/url>          Tüm uygun araçlarla tara + 0–10 risk skoru
  guide                          Tüm bulgular için toplu kapatma rehberi
  diff <ip/url>                  Son iki taramayı karşılaştır (yeni/kapanan)

  \x1b[33m─── YAMA (SAFE KİPİ) ───\x1b[0m
  safe <ip/url veya dosya>       Yama kipine gir (tarama dosyasını yükler)
    set transport ssh|telnet     Bağlantı türü (varsayılan ssh)
    set user <ad>                Yetkili kullanıcı
    set pass                     Parola (gizli; sadece bellek)
    set key <yol>                SSH anahtarı (parola yerine)
    set file <yol>               Tarama dosyasını değiştir
    select <n,n> | select all    Kapatılacak zafiyetleri seç
    show                         Ayarları + kapatılacakları göster
    run                          Onay al, bağlan, yama uygula, doğrula, (ops.) reboot
    run --dry                    Bağlanmadan çalıştırılacak komutları göster
    rollback <log>               Bir yama log'undaki yedekleri geri yükle
    back                         Kipten çık

  \x1b[33m─── AKILLI TARAMA ───\x1b[0m
  scan <ip/domain>               Otomatik tarama (IP→Nmap, URL→ZAP)
  scan full <ip/domain>          Kapsamlı tarama (Nmap + ZAP birlikte)

  \x1b[33m─── NMAP ───\x1b[0m
  run nmap <args>                Nmap çalıştır (özel argümanlarla)
  run nmap full <hedef>          Nmap tam tarama (-sV -sC -A -O -p-)
  load nmap <dosya.xml>          Nmap XML raporunu yükle

  \x1b[33m─── ZAP ───\x1b[0m
  run zap <url>                  ZAP hızlı tarama
  run zap full <url>             ZAP tam tarama
  load zap <dosya.json>          ZAP JSON raporunu yükle

  \x1b[33m─── ZAFİYET YÖNETİMİ ───\x1b[0m
  list [sev=<level>]             Zafiyetleri listele (filtrelenebilir)
  search <anahtar kelime>        Zafiyet ara
  detail <id>                    Zafiyet detaylarını göster
  fix <id>                       Fix rehberi göster
  fix auto <id>                  Zafiyeti otomatik düzelt (varsa)
  stats                          Zafiyet istatistikleri

  \x1b[33m─── RAPORLAMA ───\x1b[0m
  report                         TXT + HTML + JSON rapor oluştur
  export json                    JSON formatında dışa aktar
  export csv                     CSV formatında dışa aktar

  \x1b[33m─── SEVERİTY SEVİYELERİ ───\x1b[0m
  \x1b[35m  CRITICAL\x1b[0m  →  Kritik (hemen müdahale gerekir)
  \x1b[31m  HIGH\x1b[0m      →  Yüksek (en kısa sürede düzeltilmeli)
  \x1b[33m  MEDIUM\x1b[0m    →  Orta (planlı düzeltme)
  \x1b[36m  LOW\x1b[0m       →  Düşük (düşük öncelikli)
  \x1b[37m  INFO\x1b[0m      →  Bilgi (kayıt amaçlı)
`);
}

function printIssueDetail(issue) {
  const sevLabel = colorSeverity(issue.severity, issue.severity.toUpperCase());
  console.log(`
\x1b[36m┌──────────────────────────────────────────────────┐\x1b[0m
\x1b[36m│\x1b[0m  \x1b[1mZafiyet Detayı - #${issue.id}\x1b[0m
\x1b[36m└──────────────────────────────────────────────────┘\x1b[0m

  \x1b[37mBaşlık      :\x1b[0m ${issue.title}
  \x1b[37mSeverity    :\x1b[0m ${sevLabel}
  \x1b[37mKaynak      :\x1b[0m ${issue.source}
  \x1b[37mKonum       :\x1b[0m ${issue.url || (issue.ip + ":" + issue.port)}
  \x1b[37mHost        :\x1b[0m ${issue.host || issue.ip || "-"}
  \x1b[37mPort        :\x1b[0m ${issue.port || "-"}
  \x1b[37mCVE         :\x1b[0m ${issue.cve || "-"}
  \x1b[37mGüvenilirlik:\x1b[0m ${issue.confidence || "-"}
  \x1b[37mFix Key     :\x1b[0m ${issue.fixKey || "-"}
  \x1b[37mZaman       :\x1b[0m ${issue.timestamp}

  \x1b[37mAçıklama    :\x1b[0m
  ${issue.description || "-"}
`);

  if (issue.fixKey && FIX_GUIDES[issue.fixKey]) {
    console.log("  \x1b[33m💡 Fix rehberi mevcut: \x1b[0m\x1b[36mfix " + issue.id + "\x1b[0m");
    if (FIX_GUIDES[issue.fixKey].autoFix) {
      console.log("  \x1b[35m⚡ Otomatik düzeltme mevcut: \x1b[0m\x1b[36mfix auto " + issue.id + "\x1b[0m");
    }
    console.log("");
  }
}

async function handleCommand(ctx, line) {
  const trimmed = line.trim();
  if (!trimmed) return;

  const [cmd, ...args] = trimmed.split(/\s+/);

  switch (cmd) {
    case "help":
      printHelp();
      break;

    case "tools":
      printTools();
      break;

    // ──────── YETKİLİ KAPSAM (SCOPE) ────────
    case "scope": {
      const sub = (args[0] || "").toLowerCase();
      try {
        if (!sub || sub === "show" || sub === "list") {
          const entries = scope.load();
          console.log(`\n\x1b[36m  ──── Yetkili Kapsam ────\x1b[0m`);
          if (entries.length === 0) {
            console.log("  \x1b[33m(tanımsız)\x1b[0m — tüm hedeflere izin veriliyor.");
            console.log("  \x1b[90mKısıtlamak için: scope add <ip | cidr | domain | *.domain>\x1b[0m\n");
          } else {
            entries.forEach(e => console.log(`   • ${e}`));
            console.log(`\n  \x1b[90mYalnızca bu hedeflere tarama/yama yapılır.\x1b[0m\n`);
          }
        } else if (sub === "add") {
          if (!args[1]) { console.log("\x1b[31m  Kullanım: scope add <ip/cidr/domain>\x1b[0m"); break; }
          const entries = scope.add(args[1]);
          console.log(`\x1b[32m  Kapsama eklendi. Toplam: ${entries.length}\x1b[0m`);
        } else if (sub === "remove" || sub === "rm") {
          if (!args[1]) { console.log("\x1b[31m  Kullanım: scope remove <girdi>\x1b[0m"); break; }
          const entries = scope.remove(args[1]);
          console.log(`\x1b[32m  Kaldırıldı. Toplam: ${entries.length}\x1b[0m`);
        } else if (sub === "clear") {
          scope.clear();
          console.log("\x1b[33m  Kapsam temizlendi (artık tüm hedeflere izin veriliyor).\x1b[0m");
        } else {
          console.log("\x1b[31m  Kullanım: scope [show] | scope add <e> | scope remove <e> | scope clear\x1b[0m");
        }
      } catch (e) {
        console.log(`\x1b[31m  ${e.message}\x1b[0m`);
      }
      break;
    }

    // ──────── ARAÇ KURULUMU ────────
    case "install": {
      const name = args[0];
      if (!name) {
        console.log("\x1b[31m  Kullanım: install <araç>\x1b[0m");
        console.log(`  \x1b[90mAraçlar: ${registry.all().map(a => a.name).join(", ")}\x1b[0m`);
        break;
      }

      const adapter = registry.get(name);
      if (!adapter) {
        console.log(`\x1b[31m  Bilinmeyen araç: '${name}'. 'tools' ile listeyi görebilirsiniz.\x1b[0m`);
        break;
      }

      if (adapter.isInstalled()) {
        console.log(`\x1b[32m  ${adapter.label} zaten kurulu.\x1b[0m`);
        break;
      }

      const res = await adapter.install(askConfirmation);
      if (res.success) {
        console.log(`\x1b[32m  [✔] ${adapter.label} kuruldu.\x1b[0m`);
        if (res.output && res.output.trim()) {
          console.log(`\x1b[90m  ${res.output.trim().split(/\r?\n/).slice(-3).join("\n  ")}\x1b[0m`);
        }
      } else if (res.cancelled) {
        console.log("\x1b[33m  Kurulum iptal edildi.\x1b[0m");
      } else if (res.manual) {
        console.log(`\x1b[33m  ${res.message}\x1b[0m`);
      } else {
        console.log(`\x1b[31m  [✘] Kurulum başarısız: ${res.error}\x1b[0m`);
        console.log(`  \x1b[33mYönetici/root ayrıcalığı gerekebilir. Elle: ${adapter.installUrl || "-"}\x1b[0m`);
      }
      break;
    }

    case "clear":
      console.clear();
      break;

    // ──────── YAMA KİPİ (SAFE) ────────
    case "safe": {
      const arg = args[0];
      if (!arg) {
        console.log("\x1b[31m  Kullanım: safe <ip/url veya tarama dosyası>\x1b[0m");
        break;
      }
      const session = new SafeSession(arg);
      let loaded = 0;
      try {
        if (fs.existsSync(arg) && fs.statSync(arg).isFile()) {
          loaded = session.loadFile(arg);
        } else {
          loaded = session.autoLoad();
        }
      } catch (e) {
        console.log(`\x1b[33m  Tarama dosyası okunamadı: ${e.message}\x1b[0m`);
      }
      ctx.safe = session;
      ctx.mode = "safe";

      if (loaded === 0) {
        console.log("\x1b[33m  Bu hedef için tarama dosyası bulunamadı. 'set file <yol>' ile yükleyin.\x1b[0m");
      } else {
        console.log(`\x1b[32m  ${loaded} zafiyet yüklendi.\x1b[0m`);
        console.log(session.renderShow());
      }
      console.log("\x1b[90m  Komutlar: set file|transport|user|pass|key|target|port, select, show, run, back\x1b[0m");
      break;
    }

    case "set": {
      if (ctx.mode !== "safe" || !ctx.safe) {
        console.log("\x1b[33m  'set' yalnızca safe kipinde kullanılır (safe <hedef>).\x1b[0m");
        break;
      }
      const key = (args[0] || "").toLowerCase();
      const val = args.slice(1).join(" ");
      const s = ctx.safe;
      try {
        switch (key) {
          case "file": {
            const n = s.loadFile(val);
            console.log(`\x1b[32m  ${n} zafiyet yüklendi.\x1b[0m`);
            break;
          }
          case "transport":
            s.setTransport(val);
            console.log(`  transport = ${s.transport}`);
            if (s.transport === "telnet") {
              console.log("\x1b[31m  [!] Telnet düz metindir; kimlik bilgisi ağda açık gider. Mümkünse ssh kullanın.\x1b[0m");
            }
            break;
          case "user":
            s.user = val;
            console.log(`  user = ${val}`);
            break;
          case "target":
            s.target = val.replace(/^https?:\/\//i, "").split("/")[0];
            console.log(`  target = ${s.target}`);
            break;
          case "port":
            s.port = parseInt(val, 10) || null;
            console.log(`  port = ${s.port}`);
            break;
          case "key":
            s.keyPath = val;
            s._pass = null;
            console.log("\x1b[32m  SSH anahtarı ayarlandı (bellekte).\x1b[0m");
            break;
          case "pass": {
            const p = await askHidden("  Parola: ");
            s._pass = p;
            s.keyPath = null;
            console.log("\x1b[32m  Parola bellekte ayarlandı (hiçbir yere yazılmadı).\x1b[0m");
            break;
          }
          default:
            console.log("\x1b[31m  Kullanım: set file|transport|user|pass|key|target|port <değer>\x1b[0m");
        }
      } catch (e) {
        console.log(`\x1b[31m  ${e.message}\x1b[0m`);
      }
      break;
    }

    case "select": {
      if (ctx.mode !== "safe" || !ctx.safe) {
        console.log("\x1b[33m  'select' yalnızca safe kipinde kullanılır.\x1b[0m");
        break;
      }
      try {
        ctx.safe.setSelection(args.join(" "));
        const sel = [...ctx.safe.selected].sort((a, b) => a - b).join(",") || "(yok)";
        console.log(`\x1b[32m  seçilen: ${sel}\x1b[0m`);
      } catch (e) {
        console.log(`\x1b[31m  ${e.message}\x1b[0m`);
      }
      break;
    }

    case "show": {
      if (ctx.mode !== "safe" || !ctx.safe) {
        console.log("\x1b[33m  'show' yalnızca safe kipinde kullanılır.\x1b[0m");
        break;
      }
      console.log(ctx.safe.renderShow());
      break;
    }

    case "rollback": {
      if (ctx.mode !== "safe" || !ctx.safe) {
        console.log("\x1b[33m  'rollback' yalnızca safe kipinde kullanılır.\x1b[0m");
        break;
      }
      const lp = args[0];
      if (!lp) {
        console.log("\x1b[31m  Kullanım: rollback <remediation-log-yolu>\x1b[0m");
        break;
      }
      if (!enforceScope(ctx.safe.target, "rollback")) break;
      try {
        const res = await ctx.safe.rollback(lp, askConfirmation);
        if (res.none) {
          console.log("\x1b[33m  Log'da geri yüklenebilir yedek (.bak) bulunamadı.\x1b[0m");
        } else if (res.cancelled) {
          /* kullanıcı iptal etti */
        } else if (res.connectError) {
          console.log(`\x1b[31m  Bağlantı hatası: ${res.connectError}\x1b[0m`);
        } else {
          console.log(`\n\x1b[32m  Geri yüklenen (${res.restored.length}):\x1b[0m ${res.restored.join(", ") || "-"}`);
          if (res.failed.length) {
            console.log("\x1b[31m  Başarısız:\x1b[0m");
            res.failed.forEach(x => console.log(`   ${x.f} — ${x.reason}`));
          }
          if (res.dryCommands) console.log(`\x1b[90m  [dryrun] ${res.dryCommands.join("; ")}\x1b[0m`);
          console.log(`\x1b[90m  Log: ${res.logPath}\x1b[0m\n`);
        }
      } catch (e) {
        console.log(`\x1b[31m  ${e.message}\x1b[0m`);
      }
      break;
    }

    case "back": {
      if (ctx.mode === "safe" && ctx.safe) {
        ctx.safe.wipeCredentials();
        ctx.safe = null;
      }
      ctx.mode = "normal";
      break;
    }

    // ──────── TAM TARAMA (ORKESTRATÖR) ────────
    case "start": {
      const target = args[0];
      if (!target) {
        console.log("\x1b[31m  Kullanım: start <ip/domain/url>\x1b[0m");
        break;
      }

      if (!enforceScope(target, "tarama")) break;

      const type = isIP(target) ? "ip" : (isURL(target) ? "url" : "ip");
      const host = target.replace(/^https?:\/\//i, "").split("/")[0];
      const url = /^https?:\/\//i.test(target) ? target : `http://${target}`;

      console.log(`\n\x1b[36m  [*] XAS tam tarama başlıyor: ${target}  (${type.toUpperCase()})\x1b[0m`);
      console.log(`  \x1b[33m[!] Yalnızca sahibi olduğunuz veya yetkili olduğunuz sistemleri tarayın.\x1b[0m`);

      const tools = registry.managedFor(type);
      if (tools.length === 0) {
        console.log("\x1b[31m  Bu hedef türü için uygun araç yok.\x1b[0m");
        break;
      }

      const before = ctx.issues.length;
      let idx = 0;
      for (const adapter of tools) {
        idx++;
        const tgt = adapter.category === "web" ? url : host;
        if (!adapter.isInstalled()) {
          console.log(`\n\x1b[90m  [${idx}/${tools.length}] ${adapter.label} kurulu değil, atlanıyor (install ${adapter.name}).\x1b[0m`);
          continue;
        }
        console.log(`\n\x1b[32m  [${idx}/${tools.length}] ${adapter.label} çalışıyor...\x1b[0m`);
        try {
          await adapter.run(ctx, tgt);
        } catch (e) {
          console.log(`\x1b[31m  ${adapter.label} hatası: ${e.message}\x1b[0m`);
        }
      }

      const added = ctx.issues.length - before;
      console.log(`\n\x1b[32m  [✔] Tarama tamamlandı. Bu taramada ${added} bulgu, toplam ${ctx.issues.length}.\x1b[0m`);
      printRiskCard(target, ctx.issues);

      if (ctx.issues.length > 0) {
        try {
          const file = scanStore.writeScan(target, ctx.issues);
          console.log(`  \x1b[90mTarama dosyası: ${file}\x1b[0m`);
          console.log(`  \x1b[36mYama için:\x1b[0m safe ${target}\n`);
        } catch (e) {
          console.log(`\x1b[33m  Tarama dosyası yazılamadı: ${e.message}\x1b[0m`);
        }
      }

      ctx.mode = "scan";
      break;
    }

    // ──────── GUI ARAÇ BAŞLAT ────────
    case "launch": {
      const name = args[0];
      if (!name) {
        const guis = registry.launchable().map(a => a.name).join(", ");
        console.log("\x1b[31m  Kullanım: launch <araç>\x1b[0m");
        console.log(`  \x1b[90mGUI araçlar: ${guis || "yok"}\x1b[0m`);
        break;
      }

      const adapter = registry.get(name);
      if (!adapter) {
        console.log(`\x1b[31m  Bilinmeyen araç: '${name}'.\x1b[0m`);
        break;
      }
      if (adapter.mode !== "launch") {
        console.log(`\x1b[33m  '${adapter.name}' terminalden yönetilir; 'run ${adapter.name} <hedef>' veya 'start' kullanın.\x1b[0m`);
        break;
      }
      if (!adapter.isInstalled()) {
        console.log(`\x1b[31m  ${adapter.label} kurulu değil. İndir: ${adapter.installUrl || "-"}\x1b[0m`);
        break;
      }

      const res = adapter.launch();
      if (res.success) {
        console.log(`\x1b[32m  ${adapter.label} başlatıldı (ayrı pencere).\x1b[0m`);
      } else {
        console.log(`\x1b[31m  ${adapter.label} başlatılamadı: ${res.error}\x1b[0m`);
      }
      break;
    }

    // ──────── AKILLI TARAMA ────────
    case "scan": {
      if (args.length === 0) {
        console.log("\x1b[31m  Kullanım: scan <ip/domain> veya scan full <ip/domain>\x1b[0m");
        break;
      }

      const isFull = args[0] === "full";
      const target = isFull ? args[1] : args[0];

      if (!target) {
        console.log("\x1b[31m  Hedef belirtilmedi.\x1b[0m");
        break;
      }

      if (!enforceScope(target, "tarama")) break;

      console.log(`\n\x1b[36m  [*] Hedef analiz ediliyor: ${target}\x1b[0m`);

      const nmap = registry.get("nmap");
      const zap = registry.get("zap");

      if (isFull) {
        // Full scan: hem Nmap hem ZAP
        console.log("\x1b[33m  [*] Kapsamlı tarama modu (Nmap + ZAP)\x1b[0m\n");

        if (nmap.isInstalled()) {
          console.log("\x1b[32m  [1/2] Nmap taraması başlatılıyor...\x1b[0m");
          await nmap.run(ctx, target, { full: true });
        } else {
          console.log("\x1b[31m  [!] Nmap kurulu değil, atlanıyor.\x1b[0m");
        }

        const zapTarget = target.startsWith("http") ? target : `http://${target}`;
        if (zap.isInstalled()) {
          console.log("\x1b[32m  [2/2] ZAP taraması başlatılıyor...\x1b[0m");
          await zap.run(ctx, zapTarget, { full: true });
        } else {
          console.log("\x1b[31m  [!] ZAP kurulu değil, atlanıyor.\x1b[0m");
        }
      } else if (isIP(target)) {
        // IP → Nmap
        if (nmap.isInstalled()) {
          console.log("\x1b[32m  [*] IP adresi algılandı → Nmap taraması başlatılıyor...\x1b[0m\n");
          await nmap.run(ctx, target);
        } else {
          console.log(`\x1b[31m  [!] Nmap kurulu değil. Kurmak için: ${nmap.installUrl}\x1b[0m`);
        }
      } else if (isURL(target)) {
        // URL → ZAP
        const zapTarget = target.startsWith("http") ? target : `http://${target}`;
        if (zap.isInstalled()) {
          console.log("\x1b[32m  [*] Web adresi algılandı → ZAP taraması başlatılıyor...\x1b[0m\n");
          await zap.run(ctx, zapTarget);
        } else {
          console.log(`\x1b[31m  [!] ZAP kurulu değil. Kurmak için: ${zap.installUrl}\x1b[0m`);
        }
      } else {
        // Ne IP ne URL, Nmap dene
        if (nmap.isInstalled()) {
          console.log("\x1b[32m  [*] Nmap ile taranıyor...\x1b[0m\n");
          await nmap.run(ctx, target);
        } else {
          console.log("\x1b[31m  [!] Nmap kurulu değil.\x1b[0m");
        }
      }

      if (ctx.issues.length > 0) {
        console.log(`\n\x1b[32m  [✔] Tarama tamamlandı. Toplam zafiyet: ${ctx.issues.length}\x1b[0m`);
        console.log("  \x1b[36mDetaylar için: list | Rehber için: fix <id>\x1b[0m\n");
        try {
          const file = scanStore.writeScan(target, ctx.issues);
          console.log(`  \x1b[90mTarama dosyası: ${file}\x1b[0m`);
        } catch (e) { /* kaydedilemezse geç */ }
      }
      ctx.mode = "scan";
      break;
    }

    // ──────── DOĞRUDAN RUN ────────
    case "run": {
      // safe kipinde 'run' = yamayı uygula ('run --dry' = bağlanmadan planı göster)
      if (ctx.mode === "safe" && ctx.safe) {
        const dry = args.includes("--dry");
        await safeApply(ctx, { dry });
        break;
      }
      const adapter = registry.get(args[0]);
      if (!adapter || adapter.mode !== "managed") {
        console.log("\x1b[31m  Kullanım: run nmap <args> | run nmap full <target> | run zap <url> | run zap full <url>\x1b[0m");
        break;
      }

      const tgt = args[1] === "full" ? args[2] : (adapter.name === "nmap" ? args[args.length - 1] : args[1]);
      if (tgt && !enforceScope(tgt, "çalıştırma")) break;

      if (args[1] === "full") {
        await adapter.run(ctx, args[2], { full: true });
      } else if (adapter.name === "nmap") {
        // Nmap: kalan argümanlar doğrudan nmap'e geçer
        await adapter.run(ctx, null, { args: args.slice(1) });
      } else {
        await adapter.run(ctx, args[1]);
      }
      break;
    }

    // ──────── LOAD ────────
    case "load":
      if (args[0] === "nmap" && args[1]) {
        try {
          const { issues, nextId } = await parseNmapFile(args[1], ctx.nextId);
          ctx.issues.push(...issues);
          ctx.nextId = nextId;
          console.log(`\x1b[32m  ✔ Nmap raporu yüklendi. Eklenen zafiyet: ${issues.length}\x1b[0m`);
        } catch (e) {
          console.log(`\x1b[31m  ✘ Hata: ${e.message}\x1b[0m`);
        }
      } else if (args[0] === "zap" && args[1]) {
        try {
          const { issues, nextId } = parseZapFile(args[1], ctx.nextId);
          ctx.issues.push(...issues);
          ctx.nextId = nextId;
          console.log(`\x1b[32m  ✔ ZAP raporu yüklendi. Eklenen zafiyet: ${issues.length}\x1b[0m`);
        } catch (e) {
          console.log(`\x1b[31m  ✘ Hata: ${e.message}\x1b[0m`);
        }
      } else {
        console.log("\x1b[31m  Kullanım: load nmap <dosya.xml> | load zap <dosya.json>\x1b[0m");
      }
      break;

    // ──────── LİSTELEME ────────
    case "list": {
      let filterSeverity = null;
      if (args[0] && args[0].startsWith("sev=")) {
        filterSeverity = args[0].split("=")[1].toLowerCase();
      }

      let list = ctx.issues;
      if (filterSeverity) {
        list = list.filter(i => i.severity === filterSeverity);
      }

      // Severity'ye göre sırala (critical→info)
      list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));

      if (list.length === 0) {
        console.log("\x1b[33m  Gösterilecek zafiyet yok.\x1b[0m");
        break;
      }

      console.log(`\n\x1b[36m  ──── Zafiyet Listesi${filterSeverity ? " (Filtre: " + filterSeverity.toUpperCase() + ")" : ""} ────\x1b[0m\n`);

      list.forEach(i => {
        const sevLabel = colorSeverity(i.severity, `[${i.severity.toUpperCase().padEnd(8)}]`);
        const idLabel = `\x1b[37m#${String(i.id).padEnd(4)}\x1b[0m`;
        const loc = i.url || `${i.ip || i.host}:${i.port || ""}`;
        const srcLabel = `\x1b[90m(${i.source})\x1b[0m`;
        console.log(`  ${idLabel} ${sevLabel} ${srcLabel} ${loc}`);
        console.log(`       \x1b[37m${i.title}\x1b[0m`);
      });

      console.log(`\n  \x1b[36mToplam: ${list.length} zafiyet.\x1b[0m`);
      console.log("  \x1b[90mDetay için: detail <id> | Fix için: fix <id>\x1b[0m\n");
      break;
    }

    // ──────── ARAMA ────────
    case "search": {
      const keyword = args.join(" ").toLowerCase();
      if (!keyword) {
        console.log("\x1b[31m  Kullanım: search <anahtar kelime>\x1b[0m");
        break;
      }

      const results = ctx.issues.filter(i =>
        i.title.toLowerCase().includes(keyword) ||
        i.description.toLowerCase().includes(keyword) ||
        (i.cve && i.cve.toLowerCase().includes(keyword)) ||
        (i.fixKey && i.fixKey.toLowerCase().includes(keyword))
      );

      if (results.length === 0) {
        console.log(`\x1b[33m  "${keyword}" ile eşleşen zafiyet bulunamadı.\x1b[0m`);
        break;
      }

      console.log(`\n\x1b[36m  ──── Arama Sonuçları: "${keyword}" (${results.length} sonuç) ────\x1b[0m\n`);
      results.forEach(i => {
        const sevLabel = colorSeverity(i.severity, `[${i.severity.toUpperCase()}]`);
        console.log(`  \x1b[37m#${i.id}\x1b[0m ${sevLabel} ${i.title}`);
      });
      console.log("");
      break;
    }

    // ──────── DETAY ────────
    case "detail": {
      const id = parseInt(args[0], 10);
      if (isNaN(id)) {
        console.log("\x1b[31m  Kullanım: detail <id>\x1b[0m");
        break;
      }
      const issue = ctx.issues.find(i => i.id === id);
      if (!issue) {
        console.log("\x1b[31m  Bu ID'ye ait zafiyet bulunamadı.\x1b[0m");
        break;
      }
      printIssueDetail(issue);
      break;
    }

    // ──────── İSTATİSTİK ────────
    case "stats": {
      if (ctx.issues.length === 0) {
        console.log("\x1b[33m  Henüz tarama yapılmamış.\x1b[0m");
        break;
      }

      const counts = {};
      ctx.issues.forEach(i => {
        counts[i.severity] = (counts[i.severity] || 0) + 1;
      });

      console.log(`\n\x1b[36m  ──── Zafiyet İstatistikleri ────\x1b[0m\n`);

      const maxCount = Math.max(...Object.values(counts));
      const severityOrder = ["critical", "high", "medium", "low", "info"];

      severityOrder.forEach(sev => {
        const count = counts[sev] || 0;
        if (count === 0) return;
        const barLen = Math.round((count / maxCount) * 20);
        const bar = "█".repeat(barLen) + "░".repeat(20 - barLen);
        console.log(`  ${colorSeverity(sev, sev.toUpperCase().padEnd(10))} ${bar} ${count}`);
      });

      console.log(`\n  \x1b[37mToplam: ${ctx.issues.length} zafiyet\x1b[0m`);

      // Kaynak bazlı dağılım
      const sources = {};
      ctx.issues.forEach(i => { sources[i.source] = (sources[i.source] || 0) + 1; });
      console.log(`\n  \x1b[36mKaynak Dağılımı:\x1b[0m`);
      Object.entries(sources).forEach(([src, cnt]) => {
        console.log(`    ${src.toUpperCase().padEnd(8)}: ${cnt}`);
      });
      console.log("");
      break;
    }

    // ──────── FIX ────────
    case "fix": {
      if (args[0] === "auto") {
        const id = parseInt(args[1], 10);
        if (isNaN(id)) {
          console.log("\x1b[31m  Kullanım: fix auto <id>\x1b[0m");
          break;
        }

        const issue = ctx.issues.find(i => i.id === id);
        if (!issue) {
          console.log("\x1b[31m  Bu ID'ye ait zafiyet bulunamadı.\x1b[0m");
          break;
        }

        if (!issue.fixKey || !FIX_GUIDES[issue.fixKey] || !FIX_GUIDES[issue.fixKey].autoFix) {
          console.log("\x1b[33m  Bu zafiyet için otomatik düzeltme (Auto-Fix) tanımlanmamış.\x1b[0m");
          console.log("  Lütfen `fix " + id + "` yazarak manuel çözüm adımlarını izleyin.");
          break;
        }

        const autoFixDef = FIX_GUIDES[issue.fixKey].autoFix;
        console.log(`\n\x1b[35m  [!] OTOMATİK DÜZELTME BAŞLATILACAK: \x1b[0m${autoFixDef.description}`);
        console.log(`  \x1b[31mUYARI: Sistem güvenlik duvarı veya servis yapılandırması değiştirilecek.\x1b[0m`);

        const ans = await askConfirmation("  Devam etmek istiyor musunuz? (E/H): ");
        if (ans.toLowerCase() === "e" || ans.toLowerCase() === "y") {
          console.log("\x1b[36m  [*] Düzeltme uygulanıyor...\x1b[0m");
          const result = applyAutoFix(autoFixDef);

          if (result.success) {
            console.log(`\x1b[32m  [✔] Otomatik düzeltme başarıyla uygulandı!\x1b[0m`);
            if (result.output && result.output.trim()) {
              console.log(`\x1b[90m  Çıktı:\n  ${result.output.trim()}\x1b[0m`);
            }
          } else {
            console.log(`\x1b[31m  [✘] Otomatik düzeltme başarısız oldu.\x1b[0m`);
            console.log(`  Hata Detayı: ${result.error}`);
            console.log(`  \x1b[33mLütfen yönetici/root ayrıcalıklarıyla çalıştırdığınızdan emin olun.\x1b[0m`);
          }
        } else {
          console.log("\x1b[33m  [*] İşlem iptal edildi.\x1b[0m");
        }
        break;
      }

      const id = parseInt(args[0], 10);
      if (isNaN(id)) {
        console.log("\x1b[31m  Kullanım: fix <id> veya fix auto <id>\x1b[0m");
        break;
      }
      const issue = ctx.issues.find(i => i.id === id);
      if (!issue) {
        console.log("\x1b[31m  Bu ID'ye ait zafiyet bulunamadı.\x1b[0m");
        break;
      }
      if (!issue.fixKey) {
        console.log("\x1b[33m  Bu zafiyet için fix rehberi tanımlanmamış.\x1b[0m");
        break;
      }
      printFixGuide(issue.fixKey);
      break;
    }

    // ──────── TOPLU REHBER ────────
    case "guide": {
      if (ctx.issues.length === 0) {
        console.log("\x1b[33m  Önce bir tarama yapın (start / scan).\x1b[0m");
        break;
      }

      const byKey = new Map();
      const noGuide = [];
      for (const issue of ctx.issues) {
        if (issue.fixKey && FIX_GUIDES[issue.fixKey]) {
          byKey.set(issue.fixKey, (byKey.get(issue.fixKey) || 0) + 1);
        } else {
          noGuide.push(issue);
        }
      }

      const keys = [...byKey.keys()].sort(
        (a, b) => (SEVERITY_ORDER[FIX_GUIDES[a].severity] ?? 99) - (SEVERITY_ORDER[FIX_GUIDES[b].severity] ?? 99)
      );

      console.log(`\n\x1b[36m  ──── Toplu Kapatma Rehberi (${keys.length} tür, ${ctx.issues.length} bulgu) ────\x1b[0m`);

      keys.forEach(k => {
        console.log(`\n  \x1b[90m(${byKey.get(k)} bulgu bu türde)\x1b[0m`);
        printFixGuide(k);
      });

      if (noGuide.length > 0) {
        console.log(`\n\x1b[33m  ─── Özel rehberi olmayan ${noGuide.length} bulgu ───\x1b[0m`);
        noGuide.forEach(i => {
          const sev = colorSeverity(i.severity, `[${i.severity.toUpperCase()}]`);
          console.log(`   \x1b[37m#${i.id}\x1b[0m ${sev} ${i.title}`);
        });
        console.log(`  \x1b[90mGenel tavsiye: ilgili servisi güncel tutun, gereksizse kapatın, erişimi kısıtlayın (firewall/allowlist).\x1b[0m\n`);
      }
      break;
    }

    // ──────── TARAMA DIFF (GEÇMİŞ) ────────
    case "diff": {
      const target = args[0];
      if (!target) {
        console.log("\x1b[31m  Kullanım: diff <ip/url>  (hedefin son iki taramasını karşılaştırır)\x1b[0m");
        break;
      }
      const recent = scanStore.findRecentFor(target, 2);
      if (recent.length < 2) {
        console.log(`\x1b[33m  Karşılaştırma için en az 2 tarama gerekli; bu hedef için ${recent.length} var.\x1b[0m`);
        break;
      }
      try {
        const [newerPath, olderPath] = recent; // en yeni önce
        const nd = scanStore.readScan(newerPath);
        const od = scanStore.readScan(olderPath);
        const d = scanStore.diffScans(od.issues, nd.issues);

        const line = i => {
          const sev = colorSeverity(i.severity, `[${i.severity.toUpperCase()}]`);
          const loc = i.url || `${i.ip || i.host || ""}${i.port ? ":" + i.port : ""}`;
          console.log(`     ${sev} ${i.title}  \x1b[90m${loc}\x1b[0m`);
        };

        console.log(`\n\x1b[36m  ──── Tarama Karşılaştırması: ${target} ────\x1b[0m`);
        console.log(`  \x1b[90mÖnceki: ${od.timestamp || olderPath}\x1b[0m`);
        console.log(`  \x1b[90mGüncel: ${nd.timestamp || newerPath}\x1b[0m`);

        console.log(`\n  \x1b[31mYeni açılan (${d.added.length}):\x1b[0m`);
        d.added.length ? d.added.forEach(line) : console.log("     \x1b[90m(yok)\x1b[0m");
        console.log(`\n  \x1b[32mKapanan (${d.resolved.length}):\x1b[0m`);
        d.resolved.length ? d.resolved.forEach(line) : console.log("     \x1b[90m(yok)\x1b[0m");
        console.log(`\n  \x1b[37mDevam eden: ${d.unchanged.length}\x1b[0m`);

        const rb = riskScorer.computeScore(od.issues);
        const ra = riskScorer.computeScore(nd.issues);
        console.log(`\n  \x1b[36mRisk (önceki → güncel):\x1b[0m ${rb.toFixed(1)} → ${ra.toFixed(1)} / 10\n`);
      } catch (e) {
        console.log(`\x1b[31m  Karşılaştırma hatası: ${e.message}\x1b[0m`);
      }
      break;
    }

    // ──────── RAPOR ────────
    case "report": {
      if (ctx.issues.length === 0) {
        console.log("\x1b[33m  Rapor oluşturmak için önce tarama yapın.\x1b[0m");
        break;
      }

      console.log("\n\x1b[36m  [*] Raporlar oluşturuluyor...\x1b[0m");

      const txt = generateTxtReport(ctx.issues);
      console.log(`  \x1b[32m✔ TXT rapor:\x1b[0m ${txt}`);

      const html = generateHtmlReport(ctx.issues);
      console.log(`  \x1b[32m✔ HTML rapor:\x1b[0m ${html}`);

      const json = generateJsonReport(ctx.issues);
      console.log(`  \x1b[32m✔ JSON rapor:\x1b[0m ${json}`);

      console.log("\n\x1b[36m  [✔] Tüm raporlar reports/ klasöründe.\x1b[0m\n");
      break;
    }

    // ──────── EXPORT ────────
    case "export": {
      if (ctx.issues.length === 0) {
        console.log("\x1b[33m  Dışa aktarmak için önce tarama yapın.\x1b[0m");
        break;
      }

      const format = (args[0] || "").toLowerCase();
      const reportsDir = path.join(__dirname, "../reports");
      if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

      if (format === "json") {
        const file = generateJsonReport(ctx.issues);
        console.log(`\x1b[32m  ✔ JSON dışa aktarıldı: ${file}\x1b[0m`);
      } else if (format === "csv") {
        let csv = "ID,Severity,Source,Title,Location,CVE,FixKey,Timestamp\n";
        ctx.issues.forEach(i => {
          const loc = i.url || `${i.ip}:${i.port}`;
          csv += `${i.id},"${i.severity}","${i.source}","${i.title.replace(/"/g, '""')}","${loc}","${i.cve || ""}","${i.fixKey || ""}","${i.timestamp}"\n`;
        });
        const file = path.join(reportsDir, "report.csv");
        fs.writeFileSync(file, csv);
        console.log(`\x1b[32m  ✔ CSV dışa aktarıldı: ${file}\x1b[0m`);
      } else {
        console.log("\x1b[31m  Kullanım: export json | export csv\x1b[0m");
      }
      break;
    }

    // ──────── ÇIKIŞ ────────
    case "exit":
    case "quit":
      console.log("\x1b[36m  Güle güle! 🛡️\x1b[0m");
      process.exit(0);

    default:
      console.log(`\x1b[31m  Bilinmeyen komut: '${cmd}'. 'help' yazarak komut listesini görebilirsiniz.\x1b[0m`);
      break;
  }
}

module.exports = {
  XasContext,
  handleCommand
};