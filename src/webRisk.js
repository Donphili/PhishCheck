import { getRiskLevel } from "./securityEngine";

// Optional online check. Set VITE_API_URL (for example http://localhost:5000)
// to send submitted URLs to the PhishCheck backend, which asks Google Web Risk.
// When it is not set, or the backend is down, PhishCheck stays fully local.
const API_URL = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

export const webRiskEnabled = Boolean(API_URL);

export async function checkWebRisk(url) {
  if (!webRiskEnabled) return null;

  try {
    const response = await fetch(`${API_URL}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(12000),
    });

    if (!response.ok) return null;

    return await response.json();
  } catch {
    return null;
  }
}

export function applyWebRisk(analysis, check) {
  if (!check) return analysis;

  if (check.status === "match") {
    const indicators = [
      ...analysis.indicators,
      {
        label: "Listed on Google Web Risk threat lists",
        points: 60,
        severity: "high",
        explanation: `Google Web Risk lists this address as: ${(check.threatTypes || []).join(", ").replaceAll("_", " ").toLowerCase() || "a known threat"}. Do not open it.`,
      },
    ];

    const score = Math.min(100, analysis.score + 60);
    const riskLevel = getRiskLevel(score);

    return {
      ...analysis,
      indicators,
      score,
      risk: riskLevel,
      riskLevel,
    };
  }

  if (check.status === "no_match") {
    return {
      ...analysis,
      safetyNote: `${analysis.safetyNote} The address was also checked against Google Web Risk and no match was found. That still does not guarantee it is safe, because new scam sites are often not listed yet.`,
    };
  }

  return analysis;
}
