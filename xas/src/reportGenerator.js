const fs = require("fs");
const path = require("path");
const riskScorer = require("./riskScorer");

function generateTxtReport(issues) {
  let txt = "═══════════════════════════════════════════════════\n";
  txt += "         XAS Security Report\n";
  txt += `         Tarih: ${new Date().toLocaleString("tr-TR")}\n`;
  txt += "═══════════════════════════════════════════════════\n\n";

  const risk = riskScorer.summarize(issues);
  txt += "─── RİSK SKORU ───\n";
  txt += `  ${risk.score.toFixed(1)} / 10   [${risk.grade.letter} - ${risk.grade.label}]\n\n`;

  // İstatistik özeti
  const counts = {};
  issues.forEach(i => {
    counts[i.severity] = (counts[i.severity] || 0) + 1;
  });

  txt += "─── ZAFİYET İSTATİSTİKLERİ ───\n";
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  severityOrder.forEach(sev => {
    if (counts[sev]) {
      txt += `  ${sev.toUpperCase().padEnd(10)}: ${counts[sev]}\n`;
    }
  });
  txt += `  ${"TOPLAM".padEnd(10)}: ${issues.length}\n\n`;

  // Detaylı zafiyet listesi
  txt += "─── ZAFİYET DETAYLARI ───\n\n";
  issues.forEach(i => {
    txt += `┌─ #${i.id} [${i.severity.toUpperCase()}]\n`;
    txt += `│  Başlık     : ${i.title}\n`;
    txt += `│  Kaynak     : ${i.source}\n`;
    txt += `│  Konum      : ${i.url || (i.ip + ":" + i.port)}\n`;
    txt += `│  Açıklama   : ${i.description}\n`;
    if (i.cve) txt += `│  CVE        : ${i.cve}\n`;
    if (i.fixKey) txt += `│  Fix Rehberi: ${i.fixKey}\n`;
    txt += `│  Zaman      : ${i.timestamp}\n`;
    txt += `└──────────────────────────────────\n\n`;
  });

  const reportsDir = path.join(__dirname, "../reports");
  if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

  const file = path.join(reportsDir, "report.txt");
  fs.writeFileSync(file, txt);
  return file;
}

function generateHtmlReport(issues) {
  const counts = {};
  issues.forEach(i => {
    counts[i.severity] = (counts[i.severity] || 0) + 1;
  });

  const sevColors = {
    critical: "#e040fb",
    high: "#ff5252",
    medium: "#ffab40",
    low: "#40c4ff",
    info: "#b0bec5"
  };

  const risk = riskScorer.summarize(issues);
  const gradeColor = { A: "#3fb950", B: "#58a6ff", C: "#ffab40", D: "#ff5252", F: "#e040fb" }[risk.grade.letter] || "#b0bec5";

  const severityOrder = ["critical", "high", "medium", "low", "info"];

  // Bar chart HTML
  const maxCount = Math.max(...Object.values(counts), 1);
  let barChart = "";
  severityOrder.forEach(sev => {
    const count = counts[sev] || 0;
    const width = Math.round((count / maxCount) * 100);
    barChart += `
      <div style="display:flex;align-items:center;margin:6px 0;">
        <span style="width:80px;font-weight:bold;color:${sevColors[sev]}">${sev.toUpperCase()}</span>
        <div style="background:${sevColors[sev]}22;border-radius:4px;flex:1;height:28px;margin-right:10px;">
          <div style="background:${sevColors[sev]};height:100%;width:${width}%;border-radius:4px;transition:width 0.5s;"></div>
        </div>
        <span style="width:30px;text-align:right;font-weight:bold;">${count}</span>
      </div>`;
  });

  let html = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>XAS Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; }
  h1 { color: #58a6ff; margin-bottom: 5px; font-size: 28px; }
  .subtitle { color: #8b949e; margin-bottom: 25px; }
  .stats-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 25px; }
  .stats-box h2 { color: #58a6ff; font-size: 16px; margin-bottom: 12px; }
  .summary { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
  .summary-item { background: #21262d; padding: 12px 20px; border-radius: 6px; text-align: center; min-width: 90px; }
  .summary-item .count { font-size: 24px; font-weight: bold; }
  .summary-item .label { font-size: 11px; text-transform: uppercase; margin-top: 4px; }
  .issue { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid; }
  .issue.critical { border-left-color: #e040fb; }
  .issue.high { border-left-color: #ff5252; }
  .issue.medium { border-left-color: #ffab40; }
  .issue.low { border-left-color: #40c4ff; }
  .issue.info { border-left-color: #b0bec5; }
  .issue h3 { font-size: 15px; margin-bottom: 8px; }
  .issue .meta { font-size: 13px; color: #8b949e; }
  .issue .meta span { margin-right: 15px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge.critical { background: #e040fb33; color: #e040fb; }
  .badge.high { background: #ff525233; color: #ff5252; }
  .badge.medium { background: #ffab4033; color: #ffab40; }
  .badge.low { background: #40c4ff33; color: #40c4ff; }
  .badge.info { background: #b0bec533; color: #b0bec5; }
  .desc { margin-top: 8px; font-size: 13px; color: #8b949e; line-height: 1.5; }
</style>
</head>
<body>
  <h1>🛡️ XAS Security Report</h1>
  <p class="subtitle">Oluşturulma: ${new Date().toLocaleString("tr-TR")} | Toplam Zafiyet: ${issues.length}</p>

  <div class="stats-box" style="border-left:6px solid ${gradeColor};">
    <h2>🎯 Risk Skoru</h2>
    <div style="font-size:34px;font-weight:bold;color:${gradeColor};">${risk.score.toFixed(1)} <span style="font-size:18px;color:#8b949e;">/ 10</span></div>
    <div style="color:${gradeColor};font-weight:bold;margin-top:4px;">${risk.grade.letter} — ${escapeHtml(risk.grade.label)}</div>
  </div>

  <div class="stats-box">
    <h2>📊 Zafiyet Dağılımı</h2>
    <div class="summary">`;

  severityOrder.forEach(sev => {
    const count = counts[sev] || 0;
    html += `
      <div class="summary-item">
        <div class="count" style="color:${sevColors[sev]}">${count}</div>
        <div class="label" style="color:${sevColors[sev]}">${sev}</div>
      </div>`;
  });

  html += `
    </div>
    ${barChart}
  </div>

  <h2 style="color:#58a6ff;margin-bottom:15px;">📋 Zafiyet Listesi</h2>`;

  issues.forEach(i => {
    html += `
  <div class="issue ${i.severity}">
    <h3><span class="badge ${i.severity}">${i.severity.toUpperCase()}</span> ${escapeHtml(i.title)}</h3>
    <div class="meta">
      <span>🆔 #${i.id}</span>
      <span>📡 ${escapeHtml(i.source)}</span>
      <span>📍 ${escapeHtml(i.url || (i.ip + ":" + i.port))}</span>
      ${i.cve ? `<span>🔑 ${escapeHtml(i.cve)}</span>` : ""}
      <span>🕐 ${i.timestamp}</span>
    </div>
    <div class="desc">${escapeHtml(i.description)}</div>
  </div>`;
  });

  html += `
</body>
</html>`;

  const reportsDir = path.join(__dirname, "../reports");
  if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

  const file = path.join(reportsDir, "report.html");
  fs.writeFileSync(file, html);
  return file;
}

function generateJsonReport(issues) {
  const risk = riskScorer.summarize(issues);
  const report = {
    tool: "XAS Security Scanner",
    version: "2.0.0",
    generatedAt: new Date().toISOString(),
    totalIssues: issues.length,
    risk: { score: risk.score, grade: risk.grade.letter, label: risk.grade.label },
    summary: {},
    issues: issues.map(i => ({
      id: i.id,
      severity: i.severity,
      source: i.source,
      title: i.title,
      description: i.description,
      location: i.url || `${i.ip}:${i.port}`,
      cve: i.cve,
      fixKey: i.fixKey,
      confidence: i.confidence,
      timestamp: i.timestamp
    }))
  };

  const severities = ["critical", "high", "medium", "low", "info"];
  severities.forEach(sev => {
    report.summary[sev] = issues.filter(i => i.severity === sev).length;
  });

  const reportsDir = path.join(__dirname, "../reports");
  if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

  const file = path.join(reportsDir, "report.json");
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  return file;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

module.exports = {
  generateTxtReport,
  generateHtmlReport,
  generateJsonReport
};