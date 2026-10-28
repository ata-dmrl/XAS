// src/tools/adapters/nbtscan.js
// NetBIOS tarayıcı — bir ağdaki NetBIOS/SMB bilgi ifşasını tespit eder.
const { Adapter } = require("../Adapter");
const { Issue } = require("../../issue");

class NbtscanAdapter extends Adapter {
  constructor() {
    super({
      name: "nbtscan",
      label: "nbtscan",
      category: "recon",
      binary: "nbtscan",
      versionCmd: "nbtscan -h",
      aptPackage: "nbtscan",
      installUrl: "http://unixwiz.net/tools/nbtscan.html",
      mode: "managed",
      targetTypes: ["ip"]
    });
  }

  // Yakalanan metni Issue'lara çevirir. (ctx'ten bağımsız, test edilebilir)
  parse(text, startId) {
    const issues = [];
    let id = startId;
    const lineRe = /^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(.*)$/;

    for (const raw of String(text).split(/\r?\n/)) {
      const line = raw.trim();
      const m = line.match(lineRe);
      if (!m) continue;

      const ip = m[1];
      const name = m[2];
      const rest = m[3].trim();
      const macMatch = rest.match(/([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i);
      const mac = macMatch ? macMatch[1] : "";

      issues.push(new Issue({
        id: id++,
        source: "nbtscan",
        ip,
        port: 137,
        severity: "low",
        title: `NetBIOS/SMB Bilgi İfşası: ${name}`,
        description: `Host ${ip} NetBIOS isteklerine yanıt veriyor. İsim: ${name}${mac ? `, MAC: ${mac}` : ""}. ` +
          `NetBIOS (137/UDP) üzerinden ağ, makine ve kullanıcı adları sızabilir.`,
        fixKey: "smb"
      }));
    }

    return { issues, nextId: id };
  }

  async run(ctx, target) {
    const { output } = await this.spawnTool(this.binary, [target], {
      title: `nbtscan: ${target}`,
      capture: true
    });

    const { issues, nextId } = this.parse(output, ctx.nextId);
    ctx.issues.push(...issues);
    ctx.nextId = nextId;
    console.log(`\nToplam ${issues.length} yeni zafiyet eklendi.`);
    return issues;
  }
}

module.exports = NbtscanAdapter;
