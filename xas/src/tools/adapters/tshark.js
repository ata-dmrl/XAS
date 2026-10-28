// src/tools/adapters/tshark.js
// Wireshark'ın komut satırı karşılığı. Hedefe ait trafiği kısa süre yakalar,
// protokol hiyerarşisini analiz eder ve şifresiz (düz metin) protokolleri raporlar.
// NOT: Bir ağ arayüzü ve (genellikle) yükseltilmiş yetki gerektirir.
const path = require("path");
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

// Şifresiz protokoller → önem + varsa fix rehberi.
const CLEARTEXT = {
  telnet: { severity: "high", fixKey: "telnet" },
  ftp: { severity: "high", fixKey: "ftp" },
  "ftp-data": { severity: "high", fixKey: "ftp" },
  tftp: { severity: "medium", fixKey: null },
  snmp: { severity: "medium", fixKey: null },
  pop: { severity: "medium", fixKey: null },
  imap: { severity: "medium", fixKey: null },
  smtp: { severity: "low", fixKey: null },
  http: { severity: "low", fixKey: "missing_headers" }
};

class TsharkAdapter extends Adapter {
  constructor() {
    super({
      name: "tshark",
      label: "tshark (Wireshark)",
      category: "traffic",
      binary: "tshark",
      versionCmd: "tshark -v",
      aptPackage: "tshark",
      installUrl: "https://www.wireshark.org/download.html",
      mode: "managed",
      targetTypes: ["ip", "url"]
    });
    this.duration = 15; // saniye
    this.iface = null;  // opts.iface ile override edilebilir
  }

  hostOf(target) {
    if (!target) return target;
    try {
      if (/^https?:\/\//i.test(target)) return new URL(target).hostname;
    } catch { /* düz host olarak kullan */ }
    return target.replace(/^https?:\/\//i, "").split("/")[0];
  }

  // `tshark -D` çıktısından ilk arayüz numarasını bulur.
  parseInterface(text) {
    for (const line of String(text).split(/\r?\n/)) {
      const m = line.trim().match(/^(\d+)\./);
      if (m) return m[1];
    }
    return null;
  }

  // io,phs (protokol hiyerarşisi) çıktısını ayrıştırır.
  parse(text, startId, target) {
    const issues = [];
    let id = startId;
    const seen = new Set();

    for (const raw of String(text).split(/\r?\n/)) {
      const m = raw.match(/^(\s*)([a-z0-9][a-z0-9._-]*)\s+frames:(\d+)/i);
      if (!m) continue;

      const proto = m[2].toLowerCase();
      const frames = Number(m[3]);
      if (frames <= 0 || seen.has(proto)) continue;

      const info = CLEARTEXT[proto];
      if (!info) continue;
      seen.add(proto);

      issues.push(new Issue({
        id: id++,
        source: "tshark",
        host: target || "",
        severity: info.severity,
        title: `Şifresiz protokol gözlemlendi: ${proto.toUpperCase()}`,
        description: `Yakalanan trafikte ${proto.toUpperCase()} (${frames} paket) düz metin olarak görüldü. ` +
          `Şifresiz protokoller, ağ dinleyen (MITM) saldırganlara kimlik bilgisi ve veri sızdırabilir.`,
        fixKey: info.fixKey
      }));
    }

    return { issues, nextId: id };
  }

  async resolveIface(optIface) {
    if (optIface) return String(optIface);
    if (this.iface) return String(this.iface);
    const { output } = await this.spawnTool(this.binary, ["-D"], { capture: true, quiet: true });
    return this.parseInterface(output);
  }

  async run(ctx, target, opts = {}) {
    const host = this.hostOf(target);
    const iface = await this.resolveIface(opts.iface);
    if (!iface) {
      console.log("\x1b[33m  tshark için ağ arayüzü belirlenemedi; bu araç atlanıyor. " +
        "(opts.iface ile arayüz verebilirsiniz.)\x1b[0m");
      return [];
    }

    const duration = opts.duration || this.duration;
    const pcap = path.join(this.rootDir, "tshark_capture.pcap");

    console.log(`\n--- tshark: ${host} trafiği ${duration}s yakalanıyor (arayüz ${iface}) ---\n`);
    await this.spawnTool(this.binary, [
      "-i", iface, "-a", `duration:${duration}`, "-f", `host ${host}`, "-w", pcap
    ], { title: null });

    // Yakalanan dosyayı protokol hiyerarşisi için analiz et
    const { output } = await this.spawnTool(this.binary, ["-r", pcap, "-q", "-z", "io,phs"], {
      capture: true,
      quiet: true
    });

    const { issues, nextId } = this.parse(output, ctx.nextId, host);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`Toplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = TsharkAdapter;
