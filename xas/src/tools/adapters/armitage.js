// src/tools/adapters/armitage.js
// GUI araç — Metasploit'in grafik arayüzü. XAS yalnızca başlatır; otomasyon/sömürü yapmaz.
const { Adapter } = require("../Adapter");

class ArmitageAdapter extends Adapter {
  constructor() {
    super({
      name: "armitage",
      label: "Armitage",
      category: "exploit",
      binary: "armitage",
      versionCmd: "armitage --version",
      aptPackage: "armitage",
      installUrl: "https://www.kali.org/tools/armitage/",
      mode: "launch"
    });
  }
}

module.exports = ArmitageAdapter;
