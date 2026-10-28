// src/safe/transports/index.js
// Uzaktan yönetim bağlantı türleri (transport) kayıt noktası.
const SshTransport = require("./ssh");
const TelnetTransport = require("./telnet");
const DryRunTransport = require("./dryrun");

const TRANSPORTS = {
  ssh: SshTransport,
  telnet: TelnetTransport,
  dryrun: DryRunTransport
  // winrm: ileride eklenecek
};

function available() {
  return Object.keys(TRANSPORTS).concat(["winrm"]);
}

function create(name) {
  const key = String(name || "").toLowerCase();
  if (key === "winrm") {
    throw new Error("WinRM transport henüz desteklenmiyor (yakında).");
  }
  const T = TRANSPORTS[key];
  if (!T) throw new Error(`Bilinmeyen bağlantı türü: ${name}. Seçenekler: ${available().join(", ")}`);
  return new T();
}

module.exports = { create, available };
