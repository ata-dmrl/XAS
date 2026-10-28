// src/safe/transports/ssh.js
// SSH transport (ssh2 kütüphanesi ile). Parola/anahtar yalnızca bellekte tutulur.
const fs = require("fs");

class SshTransport {
  constructor() {
    this.name = "ssh";
    this.insecure = false;
    this.conn = null;
  }

  async connect({ host, port = 22, user, password, keyPath }) {
    let Client;
    try {
      ({ Client } = require("ssh2"));
    } catch {
      throw new Error("ssh2 kütüphanesi kurulu değil. 'npm install ssh2' çalıştırın.");
    }

    const cfg = { host, port, username: user, readyTimeout: 20000 };
    if (keyPath) {
      cfg.privateKey = fs.readFileSync(keyPath);
    } else {
      cfg.password = password;
    }

    this.conn = new Client();
    await new Promise((resolve, reject) => {
      this.conn
        .on("ready", resolve)
        .on("error", err => reject(new Error(`SSH bağlantısı başarısız: ${err.message}`)))
        .connect(cfg);
    });
    return { success: true };
  }

  exec(command) {
    return new Promise((resolve, reject) => {
      this.conn.exec(command, (err, stream) => {
        if (err) return reject(err);
        let stdout = "";
        let stderr = "";
        stream
          .on("data", d => { stdout += d.toString(); })
          .on("close", code => resolve({ code: code == null ? 0 : code, stdout, stderr }));
        stream.stderr.on("data", d => { stderr += d.toString(); });
      });
    });
  }

  async disconnect() {
    if (this.conn) {
      try { this.conn.end(); } catch { /* yok say */ }
      this.conn = null;
    }
  }
}

module.exports = SshTransport;
