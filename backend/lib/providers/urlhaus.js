export const URLHAUS_NAME = "URLhaus (abuse.ch)";

// URLhaus lists URLs that distribute malware. It does not cover phishing.
export async function checkUrlhaus(url, { authKey, fetchImpl = fetch, timeoutMs = 8000 }) {
  if (!authKey) return { id: "urlhaus", name: URLHAUS_NAME, status: "disabled" };

  const response = await fetchImpl("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: {
      "Auth-Key": authKey,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ url }).toString(),
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    return {
      id: "urlhaus",
      name: URLHAUS_NAME,
      status: "unavailable",
      providerStatus: response.status,
    };
  }

  const data = await response.json();

  if (data.query_status === "ok") {
    return {
      id: "urlhaus",
      name: URLHAUS_NAME,
      status: "match",
      threats: ["malware distribution"],
      note: data.url_status === "offline" ? "The link is listed but appears to be offline now." : "",
    };
  }

  if (data.query_status === "no_results") {
    return { id: "urlhaus", name: URLHAUS_NAME, status: "no_match", threats: [] };
  }

  return { id: "urlhaus", name: URLHAUS_NAME, status: "unavailable" };
}
