import { MIN_FOR_DETAILS } from "./ids.js";

const DAY = 24 * 60 * 60 * 1000;

// Turns anonymous quiz results into the numbers a manager sees. With fewer
// than MIN_FOR_DETAILS results only counts are shown, so nobody can work out
// one person's score.
export function summarizeResults(rows, now = Date.now()) {
  const times = rows.map((row) => Date.parse(row.created_at));

  const weekly = [0, 0, 0, 0];

  for (const time of times) {
    const weeksAgo = Math.floor((now - time) / (7 * DAY));

    if (weeksAgo >= 0 && weeksAgo < 4) weekly[weeksAgo] += 1;
  }

  const base = {
    completions: rows.length,
    completionsLast30Days: times.filter((time) => now - time <= 30 * DAY).length,
    weekly,
    minForDetails: MIN_FOR_DETAILS,
  };

  if (rows.length < MIN_FOR_DETAILS) {
    return { ...base, enoughData: false };
  }

  const points = rows.reduce((sum, row) => sum + row.score, 0);
  const possible = rows.reduce((sum, row) => sum + row.total, 0);
  const strong = rows.filter((row) => row.score / row.total >= 0.75).length;

  const missedCounts = new Map();

  for (const row of rows) {
    for (const id of row.missed || []) {
      missedCounts.set(id, (missedCounts.get(id) || 0) + 1);
    }
  }

  const mostMissed = [...missedCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 3)
    .map(([id, count]) => ({
      id,
      count,
      percent: Math.round((100 * count) / rows.length),
    }));

  return {
    ...base,
    enoughData: true,
    averagePercent: Math.round((100 * points) / possible),
    strongPercent: Math.round((100 * strong) / rows.length),
    languages: {
      en: rows.filter((row) => row.language === "en").length,
      ar: rows.filter((row) => row.language === "ar").length,
    },
    mostMissed,
  };
}
