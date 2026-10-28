// test/core.test.js — riskScorer ve SafeSession (dry-run) birim testleri
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const rs = require("../src/riskScorer");
const { SafeSession } = require("../src/safe/SafeSession");

const mk = sev => ({ severity: sev });

test("riskScorer: boş liste 0 (A)", () => {
  assert.strictEqual(rs.computeScore([]), 0);
  assert.strictEqual(rs.grade(0).letter, "A");
});

test("riskScorer: tek critical ~9.5 (F)", () => {
  const s = rs.computeScore([mk("critical")]);
  assert.strictEqual(s, 9.5);
  assert.strictEqual(rs.grade(s).letter, "F");
});

test("riskScorer: en kötü baskın + hacim tavanı 10 geçmez", () => {
  const s = rs.computeScore([mk("critical"), mk("high"), mk("high"), mk("high")]);
  assert.ok(s <= 10 && s >= 9.5);
});

test("riskScorer: 2 low düşük kalır (B bandı)", () => {
  const s = rs.computeScore([mk("low"), mk("low")]);
  assert.ok(s < 4, "2 low 4 altında");
});

test("SafeSession: dosya yükleme + severity sıralı numaralandırma", () => {
  const scan = {
    target: "10.0.0.5",
    issues: [
      { id: 1, severity: "high", title: "FTP", port: 21, fixKey: "ftp" },
      { id: 2, severity: "critical", title: "Telnet", port: 23, fixKey: "telnet" },
      { id: 3, severity: "low", title: "Info", port: 137, fixKey: null }
    ]
  };
  const file = path.join(os.tmpdir(), `xas-safe-${Date.now()}.json`);
  fs.writeFileSync(file, JSON.stringify(scan));

  const s = new SafeSession("10.0.0.5");
  const n = s.loadFile(file);
  fs.rmSync(file, { force: true });

  assert.strictEqual(n, 3);
  assert.strictEqual(s.items[0].issue.severity, "critical", "critical ilk sırada");
  assert.strictEqual(s.items[0].n, 1);
});

test("SafeSession: seçim doğrulaması (geçersiz numara hata)", () => {
  const scan = { target: "t", issues: [{ id: 1, severity: "high", title: "FTP", port: 21, fixKey: "ftp" }] };
  const file = path.join(os.tmpdir(), `xas-safe2-${Date.now()}.json`);
  fs.writeFileSync(file, JSON.stringify(scan));
  const s = new SafeSession("t");
  s.loadFile(file);
  fs.rmSync(file, { force: true });

  s.setSelection("all");
  assert.strictEqual(s.selected.size, 1);
  assert.throws(() => s.setSelection("5"), /Geçersiz sıra/);
});

test("SafeSession: dry-run run plan + log + kimlik silme", async () => {
  const scan = {
    target: "10.0.0.5",
    issues: [
      { id: 1, severity: "critical", title: "Telnet", port: 23, fixKey: "telnet" },
      { id: 2, severity: "high", title: "FTP", port: 21, fixKey: "ftp" },
      { id: 3, severity: "high", title: "Postgres", port: 5432, fixKey: null }
    ]
  };
  const file = path.join(os.tmpdir(), `xas-safe3-${Date.now()}.json`);
  fs.writeFileSync(file, JSON.stringify(scan));

  const s = new SafeSession("10.0.0.5");
  s.loadFile(file);
  fs.rmSync(file, { force: true });
  s.setTransport("dryrun");
  s.setSelection("1,2,3");
  s._pass = "gizli";

  const res = await s.run(async () => "e", { reboot: false });

  assert.strictEqual(res.applied.length, 2, "telnet+ftp yamalanır");
  assert.strictEqual(res.skipped.length, 1, "fixKey'siz #3 atlanır");
  assert.ok(res.dryCommands.length > 0, "dry komutlar üretildi");
  assert.ok(fs.existsSync(res.logPath), "denetim log'u yazıldı");

  const log = fs.readFileSync(res.logPath, "utf8");
  assert.ok(!/gizli/.test(log), "parola log'a yazılmamalı");
  assert.strictEqual(s._pass, null, "run sonunda parola bellekten silinmeli");

  fs.rmSync(res.logPath, { force: true });
});
