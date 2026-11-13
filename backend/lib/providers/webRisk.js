export const WEB_RISK_NAME = "Google Web Risk";

const THREAT_LABELS = {
  SOCIAL_ENGINEERING: "phishing or social engineering",
  MALWARE: "malware",
  UNWANTED_SOFTWARE: "unwanted software",
};

export async function checkWebRisk(url, { apiKey, fetchImpl = fetch, timeoutMs = 8000 }) {
  if (!apiKey) return { id: "webrisk", name: WEB_RISK_NAME, status: "disabled" };

  const endpoint = new URL("https://webrisk.googleapis.com/v1/uris:search");

  endpoint.searchParams.set("uri", url);

  for (const type of Object.keys(THREAT_LABELS)) {
    endpoint.searchParams.append("threatTypes", type);
  }

  const response = await fetchImpl(endpoint, {
    headers: { "x-goog-api-key": apiKey },
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    return {
      id: "webrisk",
      name: WEB_RISK_NAME,
      status: "unavailable",
      providerStatus: response.status,
    };
  }

  const data = await response.json();
  const threats = (data.threat?.threatTypes || [])
    .map((type) => THREAT_LABELS[type])
    .filter(Boolean);

  return {
    id: "webrisk",
    name: WEB_RISK_NAME,
    status: threats.length > 0 ? "match" : "no_match",
    threats,
  };
}
