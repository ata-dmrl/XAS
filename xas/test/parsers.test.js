// test/parsers.test.js — tüm parser'lar için birim testleri (gerçek araç çıktısı örnekleriyle)
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { parseNmapFile } = require("../src/parsers/nmap");
const { parseZapFile } = require("../src/parsers/zap");
const registry = require("../src/tools/registry");

function tmpFile(name, content) {
  const p = path.join(os.tmpdir(), `xas-test-${Date.now()}-${name}`);
  fs.writeFileSync(p, content);
  return p;
}

test("nmap parser: açık portlar Issue olur, kapalı atlanır, fixKey eşlenir", async () => {
  const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>`;
  const file = tmpFile("nmap.xml", xml);
  const { issues } = await parseNmapFile(file, 1);
  fs.rmSync(file, { force: true });

  assert.strictEqual(issues.length, 2, "yalnızca 2 açık port");
  const telnet = issues.find(i => String(i.port) === "23");
  assert.strictEqual(telnet.fixKey, "telnet");
  assert.strictEqual(telnet.severity, "high");
  const http = issues.find(i => String(i.port) === "80");
  assert.strictEqual(http.severity, "medium", "haritada olmayan port medium");
});

test("zap parser: riskdesc 'High (Medium)' doğru severity verir (regresyon)", () => {
  const json = JSON.stringify({
    site: [{
      "@name": "http://t",
      alerts: [
        { name: "SQL Injection", riskdesc: "High (Medium)", desc: "x", instances: [{ uri: "http://t/x" }] },
        { name: "X-Frame-Options Header Not Set", riskdesc: "Low (Medium)", desc: "y" }
      ]
    }]
  });
  const file = tmpFile("zap.json", json);
  const { issues } = parseZapFile(file, 1);
  fs.rmSync(file, { force: true });

  const sqli = issues.find(i => i.title.includes("SQL"));
  assert.strictEqual(sqli.severity, "critical", "High -> critical (riskdesc parantezli)");
  assert.strictEqual(sqli.fixKey, "sql_injection");
  const hdr = issues.find(i => i.title.includes("X-Frame"));
  assert.strictEqual(hdr.severity, "medium", "Low -> medium");
  assert.strictEqual(hdr.fixKey, "missing_headers");
});

test("nbtscan parser: yanıt veren host başına bir Issue", () => {
  const out = `IP address       NetBIOS Name     Server    User
192.168.1.10     FILESRV          <server>  <unknown>  00:11:22:33:44:55
192.168.1.20     PRINTER01        <server>  <unknown>  aa:bb:cc:dd:ee:ff`;
  const { issues } = registry.get("nbtscan").parse(out, 1);
  assert.strictEqual(issues.length, 2);
  assert.strictEqual(issues[0].fixKey, "smb");
});

test("nikto parser: CSV satırları anahtar kelimeyle sınıflanır", () => {
  const csv = `"localhost","127.0.0.1","80","","GET","/","The anti-clickjacking X-Frame-Options header is not present."
"localhost","127.0.0.1","80","","GET","/backup/","Directory indexing found."`;
  const { issues } = registry.get("nikto").parse(csv, 1);
  assert.strictEqual(issues.length, 2);
  assert.strictEqual(issues[0].fixKey, "missing_headers");
  assert.strictEqual(issues[1].fixKey, "directory_listing");
});

test("sqlmap parser: zafiyet varsa critical, yoksa boş", () => {
  const vuln = `sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind`;
  const r1 = registry.get("sqlmap").parse(vuln, 1, "http://t?id=1");
  assert.strictEqual(r1.issues.length, 1);
  assert.strictEqual(r1.issues[0].severity, "critical");
  assert.strictEqual(r1.issues[0].fixKey, "sql_injection");

  const clean = registry.get("sqlmap").parse("all tested parameters do not appear to be injectable", 1, "http://t");
  assert.strictEqual(clean.issues.length, 0);
});

test("gobuster parser: hassas yollar high + admin_panel", () => {
  const out = `/admin                (Status: 200) [Size: 1234]
/images               (Status: 301) [Size: 0]`;
  const { issues } = registry.get("gobuster").parse(out, 1, "http://t/");
  const admin = issues.find(i => i.url.endsWith("/admin"));
  assert.strictEqual(admin.severity, "high");
  assert.strictEqual(admin.fixKey, "admin_panel");
  const img = issues.find(i => i.url.endsWith("/images"));
  assert.strictEqual(img.severity, "low");
});

test("tshark parser: şifresiz protokoller raporlanır", () => {
  const out = `eth   frames:100 bytes:5000
  ip   frames:100 bytes:5000
    tcp   frames:80 bytes:4000
      telnet   frames:10 bytes:1000
      http   frames:5 bytes:2000`;
  const { issues } = registry.get("tshark").parse(out, 1, "10.0.0.5");
  const telnet = issues.find(i => i.title.includes("TELNET"));
  assert.ok(telnet, "telnet tespit edildi");
  assert.strictEqual(telnet.severity, "high");
});

test("msfconsole parser: yalnızca pozitif [+] doğrulama satırları (muhafazakâr)", () => {
  const out = `resource> use auxiliary/scanner/smb/smb_ms17_010
resource> run
[+] 10.0.0.5:445 - Host is likely VULNERABLE to MS17-010!
resource> use auxiliary/scanner/vnc/vnc_none_auth
resource> run
[*] 10.0.0.5:5900 - not vulnerable`;
  const { issues } = registry.get("msfconsole").parse(out, 1, "10.0.0.5");
  assert.strictEqual(issues.length, 1, "sadece ms17-010 pozitif");
  assert.strictEqual(issues[0].fixKey, "smb");
  assert.strictEqual(issues[0].cve, "CVE-2017-0144");
});
