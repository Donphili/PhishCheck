import { getRiskLevel } from "./securityEngine.js";

// Optional online check. Set VITE_API_URL (for example http://localhost:5000)
// to send submitted URLs to the PhishCheck backend, which asks the threat-list
// services you configured there. When it is not set, or the backend is down,
// PhishCheck stays fully local.
const API_URL = (import.meta.env?.VITE_API_URL || "").replace(/\/$/, "");

export const API_BASE = API_URL;
export const linkCheckEnabled = Boolean(API_URL);

// Free hosting puts the backend to sleep when it is idle. Calling it as soon as
// the page opens gives it time to wake up before the first link is checked.
export function warmUpBackend() {
  if (!linkCheckEnabled) return;

  fetch(`${API_URL}/api/health`, { signal: AbortSignal.timeout(60000) }).catch(
    () => {}
  );
}

export async function checkLink(url) {
  if (!linkCheckEnabled) return null;

  try {
    const response = await fetch(`${API_URL}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) return null;

    return await response.json();
  } catch {
    return null;
  }
}

const sourcesWithStatus = (check, status) =>
  (check.sources || []).filter((source) => source.status === status);

const names = (sources) => sources.map((source) => source.name).join(", ");

const UNREACHABLE_NOTE =
  "The online threat lists could not be reached, so this result uses the local checks only.";

// A missing answer means the backend was asked and did not respond.
export function applyLinkCheck(analysis, check) {
  if (!check || !Array.isArray(check.sources)) {
    return {
      ...analysis,
      safetyNote: `${analysis.safetyNote} ${UNREACHABLE_NOTE}`,
    };
  }

  const matched = sourcesWithStatus(check, "match");
  const clean = sourcesWithStatus(check, "no_match");
  const failed = sourcesWithStatus(check, "unavailable");

  if (matched.length > 0) {
    // Wording stays cautious on purpose: these are reports, not proof.
    const indicators = [
      ...analysis.indicators,
      ...matched.map((source) => ({
        label: `Reported by ${source.name}`,
        points: 60,
        severity: "high",
        explanation: `${source.name} lists this address as suspected ${
          (source.threats || []).join(" and ") || "unsafe"
        }.${source.note ? ` ${source.note}` : ""} Do not open it.`,
      })),
    ];

    const score = Math.min(100, analysis.score + 60 * matched.length);
    const riskLevel = getRiskLevel(score);

    return {
      ...analysis,
      indicators,
      score,
      risk: riskLevel,
      riskLevel,
    };
  }

  if (clean.length > 0) {
    const missed =
      failed.length > 0 ? ` ${names(failed)} could not be reached.` : "";

    return {
      ...analysis,
      safetyNote: `${analysis.safetyNote} The address was also checked against ${names(clean)} and no match was found.${missed} That still does not guarantee it is safe, because new scam sites are often not listed yet.`,
    };
  }

  return {
    ...analysis,
    safetyNote: `${analysis.safetyNote} ${UNREACHABLE_NOTE}`,
  };
}
