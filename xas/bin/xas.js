#!/usr/bin/env node
// bin/xas.js — XAS başlatıcı/bootstrap.
// Yalnızca Node yerleşik modüllerini kullanır; böylece bağımlılıklar kurulmadan da çalışır.
// İlk çalıştırmada node_modules yoksa 'npm install' yapıp sonra uygulamayı başlatır.
"use strict";

const { existsSync } = require("fs");
const { join } = require("path");
const { execSync } = require("child_process");

const ROOT = join(__dirname, "..");

function ensureDependencies() {
  const hasNodeModules = existsSync(join(ROOT, "node_modules"));
  const hasManifest = existsSync(join(ROOT, "package.json"));
  if (hasManifest && !hasNodeModules) {
    console.log("\x1b[36m[XAS] İlk çalıştırma: bağımlılıklar kuruluyor (npm install)...\x1b[0m");
    try {
      execSync("npm install", { cwd: ROOT, stdio: "inherit" });
    } catch (e) {
      console.error("\x1b[31m[XAS] Bağımlılıklar kurulamadı. 'npm install' çıktısını kontrol edin.\x1b[0m");
      process.exit(1);
    }
  }
}

ensureDependencies();

// Uygulama ana girişini başlat (bağımlılıklar artık mevcut).
require(join(ROOT, "src", "index.js"));
