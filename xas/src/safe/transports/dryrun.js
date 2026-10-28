// src/safe/transports/dryrun.js
// Gerçek bağlantı kurmaz; çalıştırılacak komutları kaydeder ve başarı döner.
// Güvenli test ve "ne yapılacağını önden görme" için kullanılır.
class DryRunTransport {
  constructor() {
    this.name = "dryrun";
    this.insecure = false;
    this.commands = [];
  }

  async connect() {
    return { success: true };
  }

  async exec(command) {
    this.commands.push(command);
    return { code: 0, stdout: `[dry-run] ${command}`, stderr: "" };
  }

  async disconnect() {
    /* bağlantı yok */
  }
}

module.exports = DryRunTransport;
