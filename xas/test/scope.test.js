// test/scope.test.js — yetkili kapsam (allowlist) testleri
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const scope = require("../src/scope");

// Saf eşleme fonksiyonları (disk'e dokunmaz)
test("hostOf: şema/path/port ayıklanır", () => {
  assert.strictEqual(scope.hostOf("https://example.com/a/b"), "example.com");
  assert.strictEqual(scope.hostOf("http://10.0.0.5:8080"), "10.0.0.5");
  assert.strictEqual(scope.hostOf("10.0.0.5"), "10.0.0.5");
});

test("inCidr: IPv4 aralığı", () => {
  assert.strictEqual(scope.inCidr("192.168.1.50", "192.168.1.0/24"), true);
  assert.strictEqual(scope.inCidr("192.168.2.1", "192.168.1.0/24"), false);
  assert.strictEqual(scope.inCidr("10.0.0.5", "10.0.0.0/8"), true);
});

test("matchEntry: exact / cidr / wildcard", () => {
  assert.strictEqual(scope.matchEntry("10.0.0.5", "10.0.0.5"), true);
  assert.strictEqual(scope.matchEntry("10.0.0.6", "10.0.0.5"), false);
  assert.strictEqual(scope.matchEntry("192.168.1.9", "192.168.1.0/24"), true);
  assert.strictEqual(scope.matchEntry("api.example.com", "*.example.com"), true);
  assert.strictEqual(scope.matchEntry("example.com", "*.example.com"), true);
  assert.strictEqual(scope.matchEntry("evil.com", "*.example.com"), false);
});

test("isAllowed: boş kapsam izin verir; dolu kapsam zorlar (yedekle/geri yükle)", () => {
  const hadFile = fs.existsSync(scope.SCOPE_FILE);
  const backup = hadFile ? fs.readFileSync(scope.SCOPE_FILE, "utf8") : null;
  try {
    scope.clear();
    let r = scope.isAllowed("1.2.3.4");
    assert.strictEqual(r.empty, true);
    assert.strictEqual(r.allowed, true, "boş kapsam → izin");

    scope.save(["192.168.1.0/24", "*.example.com"]);
    assert.strictEqual(scope.isAllowed("192.168.1.77").allowed, true);
    assert.strictEqual(scope.isAllowed("https://app.example.com/x").allowed, true);
    assert.strictEqual(scope.isAllowed("8.8.8.8").allowed, false, "kapsam dışı reddedilir");
  } finally {
    if (backup !== null) fs.writeFileSync(scope.SCOPE_FILE, backup);
    else fs.rmSync(scope.SCOPE_FILE, { force: true });
  }
});
