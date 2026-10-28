// src/riskScorer.js
// Kural tabanlı (offline, belirleyici) risk puanlama motoru.
// Bulgulardan 0–10 arası tek bir risk skoru ve harf notu üretir.
// İleride opsiyonel bir LLM katmanına girdi olabilmesi için saf/yan etkisiz tutulmuştur.

const { SEVERITY_ORDER } = require("./issue");

// Tek bir bulgunun taban puanı (CVSS benzeri ağırlıklar).
const SEVERITY_SCORE = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  info: 0.5
};

// Harf notu eşikleri: [üst sınır (dahil), harf, etiket]
const GRADE_TABLE = [
  [2.0, "A", "Temiz / düşük risk"],
  [4.0, "B", "Kabul edilebilir"],
  [6.5, "C", "Dikkat — planlı düzeltme"],
  [8.5, "D", "Riskli — kısa sürede müdahale"],
  [10.0, "F", "Kritik — acil müdahale"]
];

function severityScore(severity) {
  return SEVERITY_SCORE[severity] != null ? SEVERITY_SCORE[severity] : SEVERITY_SCORE.info;
}

// "En kötü açık baskındır, ama adet de sayar" modeli.
// En yüksek bulgu temel puandır; kalan bulgular azalan ağırlıkla eklenir; tavan 10.
function computeScore(issues) {
  if (!issues || issues.length === 0) return 0;

  const scores = issues.map(i => severityScore(i.severity)).sort((a, b) => b - a);

  let score = scores[0];
  let weight = 0.5;
  for (let i = 1; i < scores.length; i++) {
    score += (scores[i] / 10) * weight;
    weight *= 0.6; // her ek bulgu giderek daha az katkı verir
  }

  score = Math.min(10, score);
  return Math.round(score * 10) / 10;
}

function grade(score) {
  for (const [max, letter, label] of GRADE_TABLE) {
    if (score <= max) return { letter, label };
  }
  return { letter: "F", label: "Kritik — acil müdahale" };
}

function countsBySeverity(issues) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (issues || []).forEach(i => {
    if (counts[i.severity] != null) counts[i.severity] += 1;
  });
  return counts;
}

// Önem sırasına göre en kritik N bulgu (critical → info).
function topIssues(issues, n = 3) {
  return (issues || [])
    .slice()
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99))
    .slice(0, n);
}

function summarize(issues) {
  const score = computeScore(issues);
  return {
    score,
    grade: grade(score),
    counts: countsBySeverity(issues),
    total: (issues || []).length,
    top: topIssues(issues, 3)
  };
}

module.exports = {
  SEVERITY_SCORE,
  severityScore,
  computeScore,
  grade,
  countsBySeverity,
  topIssues,
  summarize
};
