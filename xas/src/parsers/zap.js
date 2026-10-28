// src/parsers/zap.js

const fs = require("fs");
const { Issue } = require("../issue");

const ALERT_FIX_MAP = {
  "sql injection": "sql_injection",
  "command injection": "command_injection",
  "os command injection": "command_injection",
  "cross site scripting": "xss",
  "cross-site scripting": "xss",
  "xss": "xss",
  "csrf": "csrf",
  "cross-site request forgery": "csrf",
  "directory browsing": "directory_listing",
  "directory listing": "directory_listing",
  "ssl": "ssl_expired",
  "certificate": "ssl_expired",
  "tls": "ssl_expired",
  "cors": "cors_misconfig",
  "cross-origin": "cors_misconfig",
  "open redirect": "open_redirect",
  "external redirect": "open_redirect",
  "x-frame-options": "missing_headers",
  "x-content-type": "missing_headers",
  "content-security-policy": "missing_headers",
  "missing anti-clickjacking": "missing_headers",
  "security header": "missing_headers",
  "weak password": "weak_password",
  "password": "weak_password"
};

function mapZapAlertToFixKey(alert) {
  const name = (alert.name || alert.alert || "").toLowerCase();

  for (const [keyword, fixKey] of Object.entries(ALERT_FIX_MAP)) {
    if (name.includes(keyword)) return fixKey;
  }

  return null;
}

function mapZapRiskToSeverity(risk) {
  // ZAP 'riskdesc' çoğu zaman "High (Medium)" biçiminde gelir; ilk kelimeyi al.
  const r = (risk || "").toLowerCase().split("(")[0].trim();
  if (r === "high") return "critical";
  if (r === "medium") return "high";
  if (r === "low") return "medium";
  if (r === "informational" || r === "info") return "info";
  return "info";
}

function mapZapConfidence(confidence) {
  const c = (confidence || "").toLowerCase();
  if (c === "high" || c === "confirmed") return "yüksek";
  if (c === "medium") return "orta";
  if (c === "low") return "düşük";
  return "bilinmiyor";
}

function parseZapFile(filePath, startId) {
  const raw = fs.readFileSync(filePath, "utf8");
  const data = JSON.parse(raw);

  const issues = [];
  let currentId = startId;

  const sites = data.site || [];
  sites.forEach(site => {
    const host = site["@name"] || site.name || "";
    const alerts = site.alerts || site.alert || [];

    (Array.isArray(alerts) ? alerts : [alerts]).forEach(alert => {
      if (!alert) return;

      const sev = mapZapRiskToSeverity(alert.riskdesc || alert.risk);
      const fixKey = mapZapAlertToFixKey(alert);
      const confidence = mapZapConfidence(alert.confidence);

      // ZAP'ta bazen instances dizisi var
      const instances = alert.instances || alert.instance || [];
      const firstUrl = Array.isArray(instances) && instances.length > 0
        ? (instances[0].uri || instances[0].url || "")
        : (alert.url || alert.uri || "");

      issues.push(
        new Issue({
          id: currentId++,
          source: "zap",
          host,
          url: firstUrl || host,
          severity: sev,
          title: alert.name || alert.alert || "Bilinmeyen Alert",
          description: (alert.desc || alert.description || "").replace(/<[^>]*>/g, "").trim(),
          fixKey,
          confidence
        })
      );
    });
  });

  return { issues, nextId: currentId };
}

module.exports = {
  parseZapFile
};