// test/safe2.test.js — Faz 2: OS-duyarlı komut, doğrulama, önce/sonra risk, rollback
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { SafeSession } = require("../src/safe/SafeSession");

// Komuta göre yanıt veren sahte transport (gerçek bağlantı yok).
class MockTransport {
  constructor(responder) {
    this.name = "mock";
    this.insecure = false;
    this.calls = [];
    this.responder = responder;
  }
  async connect() { return { success: true }; }
  async exec(cmd) { this.calls.push(cmd); return this.responder(cmd); }
  async disconnect() { /* no-op */ }
}

function sessionWith(issues, responder) {
  const scan = { target: "10.0.0.5", issues };
  const file = path.join(os.tmpdir(), `xas-p2-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(file, JSON.stringify(scan));
  const s = new SafeSession("10.0.0.5");
  s.loadFile(file);
  fs.rmSync(file, { force: true });
  s.user = "root";
  s._pass = "x";
  s._transport = new MockTransport(responder);
  return s;
}

const OS_OK = cmd => {
  if (/uname -s/.test(cmd)) return { code: 0, stdout: "Linux", stderr: "" };
  if (/command -v apt-get/.test(cmd)) return { code: 0, stdout: "apt-get", stderr: "" };
  if (/ps -p 1/.test(cmd)) return { code: 0, stdout: "systemd", stderr: "" };
  return { code: 0, stdout: "", stderr: "" };
};

test("buildPackageUpgrade: paket yöneticisine göre komut", () => {
  const s = new SafeSession("t");
  assert.ok(s.buildPackageUpgrade(["vsftpd"], "apt-get").some(c => /install --only-upgrade -y vsftpd/.test(c)));
  assert.deepStrictEqual(s.buildPackageUpgrade(["x"], "bilinmeyen"), null);
  assert.deepStrictEqual(s.buildPackageUpgrade([], "apt-get"), []);
});

test("run --dry: bağlanmadan plan döner, komut listesi dolu", async () => {
  const s = sessionWith(
    [{ id: 1, severity: "critical", title: "Telnet", port: 23, fixKey: "telnet" }],
    OS_OK
  );
  s.setSelection("all");
  const res = await s.run(async () => "e", { dry: true });
  assert.strictEqual(res.dry, true);
  assert.strictEqual(res.plan[0].commands.length > 0, true);
  assert.strictEqual(s._transport.calls.length, 0, "dry'de hiç komut çalıştırılmaz");
});

test("run: doğrulama geçince kapatılır ve risk düşer", async () => {
  const responder = cmd => {
    if (/is-active telnet/.test(cmd)) return { code: 0, stdout: "inactive", stderr: "" };
    if (/grep -c .*anonymous_enable=NO/.test(cmd)) return { code: 0, stdout: "1", stderr: "" };
    return OS_OK(cmd);
  };
  const s = sessionWith([
    { id: 1, severity: "critical", title: "Telnet", port: 23, fixKey: "telnet" },
    { id: 2, severity: "high", title: "FTP", port: 21, fixKey: "ftp" }
  ], responder);
  s.setSelection("all");
  const res = await s.run(async () => "e", { reboot: false });

  assert.strictEqual(res.applied.length, 2);
  assert.ok(res.applied.every(a => a.verified === true), "hepsi doğrulandı");
  assert.ok(res.riskAfter < res.riskBefore, "risk düşmeli");
  assert.strictEqual(res.riskAfter, 0, "tümü kapandı → 0");
});

test("run: doğrulama geçmezse açık sayılır (risk düşmez)", async () => {
  const responder = cmd => {
    if (/is-active telnet/.test(cmd)) return { code: 0, stdout: "active", stderr: "" }; // hâlâ açık
    return OS_OK(cmd);
  };
  const s = sessionWith(
    [{ id: 1, severity: "critical", title: "Telnet", port: 23, fixKey: "telnet" }],
    responder
  );
  s.setSelection("all");
  const res = await s.run(async () => "e", { reboot: false });

  assert.strictEqual(res.applied.length, 1);
  assert.strictEqual(res.applied[0].verified, false);
  assert.strictEqual(res.riskAfter, res.riskBefore, "doğrulanamadı → açık sayılır");
});

test("run: systemd yoksa systemd gerektiren yama atlanır (failed)", async () => {
  const responder = cmd => {
    if (/ps -p 1/.test(cmd)) return { code: 0, stdout: "init", stderr: "" }; // systemd değil
    return OS_OK(cmd);
  };
  const s = sessionWith(
    [{ id: 1, severity: "critical", title: "Telnet", port: 23, fixKey: "telnet" }],
    responder
  );
  s.setSelection("all");
  const res = await s.run(async () => "e", { reboot: false });
  assert.strictEqual(res.failed.length, 1);
  assert.match(res.failed[0].reason, /systemd/);
});

test("rollback: log'daki yedekleri geri yükler", async () => {
  const logFile = path.join(os.tmpdir(), `xas-remed-${Date.now()}.log`);
  fs.writeFileSync(logFile,
    "[t] [TGT] [yedek] sudo cp -n /etc/vsftpd.conf /etc/vsftpd.conf.bak\n[t] [TGT] [yama] sudo systemctl restart vsftpd\n");

  const s = new SafeSession("10.0.0.5");
  s.user = "root";
  s._pass = "x";
  const mock = new MockTransport(() => ({ code: 0, stdout: "", stderr: "" }));
  s._transport = mock;

  const res = await s.rollback(logFile, async () => "e");
  fs.rmSync(logFile, { force: true });

  assert.deepStrictEqual(res.restored, ["/etc/vsftpd.conf"]);
  assert.ok(mock.calls.some(c => /cp \/etc\/vsftpd\.conf\.bak \/etc\/vsftpd\.conf/.test(c)));
  if (res.logPath) fs.rmSync(res.logPath, { force: true });
});
