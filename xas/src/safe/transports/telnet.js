// src/safe/transports/telnet.js
// Basit, best-effort Telnet transport (yerleşik net modülü ile).
// UYARI: Telnet kimlik bilgilerini DÜZ METİN gönderir; yalnızca güvenli/yerel ağda kullanın.
const net = require("net");

class TelnetTransport {
  constructor() {
    this.name = "telnet";
    this.insecure = true; // düz metin — ek onay gerektirir
    this.socket = null;
    this.buffer = "";
  }

  _waitFor(regex, timeout = 8000) {
    return new Promise((resolve, reject) => {
      const check = () => {
        const m = this.buffer.match(regex);
        if (m) { resolve(m); return true; }
        return false;
      };
      if (check()) return;
      const onData = () => { if (check()) cleanup(); };
      const timer = setTimeout(() => { cleanup(); reject(new Error(`Telnet beklenen istem gelmedi: ${regex}`)); }, timeout);
      const cleanup = () => { clearTimeout(timer); this.socket.removeListener("data", onData); };
      this.socket.on("data", onData);
    });
  }

  async connect({ host, port = 23, user, password }) {
    this.socket = net.createConnection({ host, port });
    this.socket.setEncoding("utf8");
    this.socket.on("data", d => { this.buffer += d; });

    await new Promise((resolve, reject) => {
      this.socket.once("connect", resolve);
      this.socket.once("error", e => reject(new Error(`Telnet bağlantısı başarısız: ${e.message}`)));
    });

    await this._waitFor(/login:|username:/i);
    this.socket.write(`${user}\n`);
    await this._waitFor(/password:/i);
    this.socket.write(`${password}\n`);
    // Kabuk istemi (ör. $ veya #) bekle
    await this._waitFor(/[$#]\s*$/);
    return { success: true };
  }

  async exec(command) {
    this.buffer = "";
    const marker = `__XAS_${Date.now()}__`;
    this.socket.write(`${command}; echo ${marker}$?\n`);
    const m = await this._waitFor(new RegExp(`${marker}(\\d+)`), 60000);
    const code = Number(m[1]);
    const stdout = this.buffer.split(marker)[0];
    return { code, stdout, stderr: "" };
  }

  async disconnect() {
    if (this.socket) {
      try { this.socket.write("exit\n"); this.socket.end(); } catch { /* yok say */ }
      this.socket = null;
    }
  }
}

module.exports = TelnetTransport;
