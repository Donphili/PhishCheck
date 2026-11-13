import { urlExpressions, sha256Latin1 } from "../canonicalize.js";

const ENDPOINT = "https://safebrowsing.googleapis.com/v5/hashes:search";

const THREAT_LABELS = {
  SOCIAL_ENGINEERING: "phishing or social engineering",
  MALWARE: "malware",
  UNWANTED_SOFTWARE: "unwanted software",
  POTENTIALLY_HARMFUL_APPLICATION: "a potentially harmful app",
};

export const SAFE_BROWSING_NAME = "Google Safe Browsing";

// Safe Browsing v5 hashes.search: only a 4-byte hash prefix of each URL
// expression is sent to Google, then full hashes are compared locally.
export async function checkSafeBrowsing(url, { apiKey, fetchImpl = fetch, timeoutMs = 8000 }) {
  if (!apiKey) return { id: "safebrowsing", name: SAFE_BROWSING_NAME, status: "disabled" };

  const expressions = urlExpressions(url);
  const fullHashes = expressions.map(sha256Latin1);
  const wanted = new Set(fullHashes.map((hash) => hash.toString("hex")));
  const prefixes = [
    ...new Set(fullHashes.map((hash) => hash.subarray(0, 4).toString("base64url"))),
  ];

  const endpoint = new URL(ENDPOINT);

  for (const prefix of prefixes) endpoint.searchParams.append("hashPrefixes", prefix);

  const response = await fetchImpl(endpoint, {
    headers: { "x-goog-api-key": apiKey },
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    return {
      id: "safebrowsing",
      name: SAFE_BROWSING_NAME,
      status: "unavailable",
      providerStatus: response.status,
    };
  }

  const data = await response.json();
  const threats = new Set();

  for (const entry of data.fullHashes || []) {
    const hex = Buffer.from(entry.fullHash || "", "base64").toString("hex");

    // A matching 4-byte prefix is not enough: the full hash must match.
    if (!wanted.has(hex)) continue;

    for (const detail of entry.fullHashDetails || []) {
      const label = THREAT_LABELS[detail.threatType];
      const attributes = detail.attributes || [];

      // Unknown threat types and canary entries must not be acted on.
      if (!label || attributes.includes("CANARY")) continue;

      threats.add(label);
    }
  }

  return {
    id: "safebrowsing",
    name: SAFE_BROWSING_NAME,
    status: threats.size > 0 ? "match" : "no_match",
    threats: [...threats],
  };
}
