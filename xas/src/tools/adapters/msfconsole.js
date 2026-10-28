// src/tools/adapters/msfconsole.js
// Metasploit — YALNIZCA DOĞRULAMA / TARAMA modu.
// Sadece auxiliary/scanner/* modülleriyle bilinen zafiyetleri DOĞRULAR (var mı/yok mu).
// Exploit modülü, oturum/shell açma veya post-exploitation KESİNLİKLE çalıştırılmaz.
const fs = require("fs");
const path = require("path");
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

// Çalıştırılacak doğrulama modülleri. Her biri tespit amaçlıdır (saldırı değil).
// positive: modülün "zafiyet var" dediği [+] satırını ayırt eden kalıp.
const CHECK_MODULES = [
  {
    module: "auxiliary/scanner/smb/smb_ms17_010",
    title: "SMB MS17-010 (EternalBlue) zafiyeti",
    severity: "critical",
    fixKey: "smb",
    cve: "CVE-2017-0144",
    positive: /vulnerable/i
  },
  {
    module: "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
    title: "RDP BlueKeep zafiyeti",
    severity: "critical",
    fixKey: "rdp",
    cve: "CVE-2019-0708",
    positive: /vulnerable/i
  },
  {
    module: "auxiliary/scanner/ftp/anonymous",
    title: "FTP anonim erişim açık",
    severity: "high",
    fixKey: "ftp",
    cve: null,
    positive: /anonymous|read|write/i
  },
  {
    module: "auxiliary/scanner/vnc/vnc_none_auth",
    title: "VNC kimlik doğrulamasız erişim",
    severity: "high",
    fixKey: "vnc",
    cve: null,
    positive: /no auth|none|free access/i
  }
];

class MsfconsoleAdapter extends Adapter {
  constructor() {
    super({
      name: "msfconsole",
      label: "Metasploit (doğrulama modu)",
      category: "exploit",
      binary: "msfconsole",
      versionCmd: "msfconsole --version",
      aptPackage: "metasploit-framework",
      installUrl: "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html",
      mode: "managed",
      targetTypes: ["ip"]
    });
  }

  // msfconsole resource çıktısını ayrıştırır. Hangi modülün çalıştığını
  // "use <modül>" satırlarından izler, sadece o modülün "pozitif" [+] satırını Issue yapar.
  parse(output, startId, target) {
    const issues = [];
    let id = startId;
    const added = new Set();
    let current = null;

    for (const raw of String(output).split(/\r?\n/)) {
      const line = raw.trim();

      const useMatch = line.match(/use\s+(auxiliary\/scanner\/\S+)/i);
      if (useMatch) {
        current = CHECK_MODULES.find(m => useMatch[1].includes(m.module)) || null;
        continue;
      }

      if (!current) continue;
      if (!line.startsWith("[+]")) continue;
      if (!current.positive.test(line)) continue;
      if (added.has(current.module)) continue;

      added.add(current.module);
      const ipMatch = line.match(/(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?/);
      const ip = ipMatch ? ipMatch[1] : (target || "");
      const port = ipMatch && ipMatch[2] ? Number(ipMatch[2]) : null;

      issues.push(new Issue({
        id: id++,
        source: "msfconsole",
        ip,
        port,
        severity: current.severity,
        title: current.title,
        description: `Metasploit doğrulama modülü (${current.module}) ${ip || target} üzerinde bu zafiyeti doğruladı. ` +
          `Tespit satırı: ${line.replace(/^\[\+\]\s*/, "")}`,
        fixKey: current.fixKey,
        cve: current.cve,
        confidence: "yüksek"
      }));
    }

    return { issues, nextId: id };
  }

  // Doğrulama modüllerini çalıştıran resource scriptini üretir.
  buildResource(target) {
    const lines = [`setg RHOSTS ${target}`];
    for (const m of CHECK_MODULES) {
      lines.push(`use ${m.module}`, "run");
    }
    lines.push("exit");
    return lines.join("\n") + "\n";
  }

  async run(ctx, target) {
    if (!target) {
      console.log("\x1b[31m  msfconsole için hedef gerekli: run msfconsole <ip>\x1b[0m");
      return [];
    }

    const rcFile = path.join(this.rootDir, "msf_xas.rc");
    fs.writeFileSync(rcFile, this.buildResource(target));

    console.log(`\n--- Metasploit doğrulama taraması: ${target} (yalnızca auxiliary modüller) ---\n`);
    const { output } = await this.spawnTool(this.binary, ["-q", "-r", rcFile], { capture: true });

    try { fs.rmSync(rcFile, { force: true }); } catch { /* sorun değil */ }

    const { issues, nextId } = this.parse(output, ctx.nextId, target);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`\nToplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = MsfconsoleAdapter;
