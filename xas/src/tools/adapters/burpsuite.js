// src/tools/adapters/burpsuite.js
// GUI araç — XAS yalnızca başlatır. (Community sürümünde otomasyon API'si yoktur.)
const { Adapter } = require("../Adapter");

class BurpsuiteAdapter extends Adapter {
  constructor() {
    super({
      name: "burpsuite",
      label: "Burp Suite",
      category: "web",
      binary: "burpsuite",
      versionCmd: "burpsuite --version",
      aptPackage: "burpsuite",
      installUrl: "https://portswigger.net/burp/communitydownload",
      mode: "launch"
    });
  }
}

module.exports = BurpsuiteAdapter;
