// src/tools/adapters/wireshark.js
// GUI araç — XAS yalnızca başlatır. (Terminalden analiz için tshark adapter'ı kullanılır.)
const { Adapter } = require("../Adapter");

class WiresharkAdapter extends Adapter {
  constructor() {
    super({
      name: "wireshark",
      label: "Wireshark",
      category: "traffic",
      binary: "wireshark",
      versionCmd: "wireshark --version",
      aptPackage: "wireshark",
      installUrl: "https://www.wireshark.org/download.html",
      mode: "launch"
    });
  }
}

module.exports = WiresharkAdapter;
