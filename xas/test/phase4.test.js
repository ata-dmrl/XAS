// test/phase4.test.js — nuclei parser, scan diff, risk'li rapor
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");

const registry = require("../src/tools/registry");
const scanStore = require("../src/scanStore");
const { generateJsonReport } = require("../src/reportGenerator");

test("nuclei parser: JSONL → Issue (severity/cve/fixKey, bozuk satır atlanır)", () => {
  const jsonl = [
    '{"template-id":"CVE-2021-1","info":{"name":"SQLi found","severity":"high","tags":["sqli","cve"],"classification":{"cve-id":["CVE-2021-1"]}},"matched-at":"http://t/x"}',
    '{"template-id":"tech","info":{"name":"Tech detect","severity":"info","tags":["tech"]},"host":"http://t"}',
    "bu satır JSON değil"
  ].join("\n");

  const { issues } = registry.get("nuclei").parse(jsonl, 1);
  assert.strictEqual(issues.length, 2);
  const sqli = issues[0];
  assert.strictEqual(sqli.severity, "high");
  assert.strictEqual(sqli.fixKey, "sql_injection");
  assert.strictEqual(sqli.cve, "CVE-2021-1");
  assert.strictEqual(sqli.url, "http://t/x");
  assert.strictEqual(issues[1].severity, "info");
});

test("scan diff: eklenen / çözülen / değişmeyen", () => {
  const oldI = [
    { source: "nmap", port: 23, fixKey: "telnet", severity: "critical", title: "Telnet" },
    { source: "nmap", port: 21, fixKey: "ftp", severity: "high", title: "FTP" }
  ];
  const newI = [
    { source: "nmap", port: 21, fixKey: "ftp", severity: "high", title: "FTP" },
    { source: "nuclei", url: "http://t/x", fixKey: "xss", severity: "high", title: "XSS" }
  ];
  const d = scanStore.diffScans(oldI, newI);
  assert.strictEqual(d.added.length, 1);
  assert.strictEqual(d.added[0].title, "XSS");
  assert.strictEqual(d.resolved.length, 1);
  assert.strictEqual(d.resolved[0].title, "Telnet");
  assert.strictEqual(d.unchanged.length, 1);
  assert.strictEqual(d.unchanged[0].title, "FTP");
});

test("JSON rapor risk skoru içerir", () => {
  const issues = [
    { id: 1, severity: "critical", source: "nmap", title: "x", description: "", url: "", ip: "1.1.1.1", port: 23, cve: null, fixKey: "telnet", timestamp: "t" }
  ];
  const file = generateJsonReport(issues);
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(data.risk, "risk alanı var");
  assert.strictEqual(typeof data.risk.score, "number");
  assert.strictEqual(data.risk.grade, "F");
});
