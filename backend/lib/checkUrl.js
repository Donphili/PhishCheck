import { checkSafeBrowsing, SAFE_BROWSING_NAME } from "./providers/safeBrowsing.js";
import { checkWebRisk, WEB_RISK_NAME } from "./providers/webRisk.js";
import { checkUrlhaus, URLHAUS_NAME } from "./providers/urlhaus.js";
import { OPENPHISH_NAME } from "./providers/openphish.js";
import { canonicalizeUrl } from "./canonicalize.js";

const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_MAX = 1000;

// Credentials and fragments are removed before anything leaves the server.
export function sanitizeForLookup(rawUrl) {
  const parsed = new URL(rawUrl);

  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";

  return parsed.href;
}

export function failureReason(error) {
  if (error?.name === "TimeoutError" || error?.name === "AbortError") {
    return "timeout";
  }

  if (error?.message === "fetch failed") return "network";

  if (error?.code === "ERR_INVALID_CHAR" || /header/i.test(error?.message || "")) {
    return "bad_key_format";
  }

  return "error";
}

function describeError(error) {
  const cause = error?.cause?.code ? ` (${error.cause.code})` : "";

  return `${error?.name || "Error"}: ${error?.message || "unknown"}${cause}`;
}

export function createChecker({ config, openPhish = null, fetchImpl = fetch, now = Date.now }) {
  const cache = new Map();

  const providers = [
    {
      id: "safebrowsing",
      name: SAFE_BROWSING_NAME,
      run: (url) => checkSafeBrowsing(url, { apiKey: config.safeBrowsingKey, fetchImpl }),
    },
    {
      id: "webrisk",
      name: WEB_RISK_NAME,
      run: (url) => checkWebRisk(url, { apiKey: config.webRiskKey, fetchImpl }),
    },
    {
      id: "urlhaus",
      name: URLHAUS_NAME,
      run: (url) => checkUrlhaus(url, { authKey: config.urlhausKey, fetchImpl }),
    },
    {
      id: "openphish",
      name: OPENPHISH_NAME,
      run: (url) =>
        openPhish
          ? openPhish.check(url)
          : { id: "openphish", name: OPENPHISH_NAME, status: "disabled" },
    },
  ];

  return async function checkUrl(rawUrl) {
    const url = sanitizeForLookup(rawUrl);
    const cacheKey = canonicalizeUrl(url).url;
    const cached = cache.get(cacheKey);

    if (cached && now() - cached.at < CACHE_TTL_MS) return cached.result;

    const settled = await Promise.allSettled(
      providers.map((provider) => provider.run(url))
    );

    const sources = settled
      .map((outcome, index) => {
        if (outcome.status === "fulfilled") return outcome.value;

        const { id, name } = providers[index];

        // The submitted URL is never logged. Only the kind of failure is.
        console.error(`Source ${id} failed: ${describeError(outcome.reason)}`);

        return {
          id,
          name,
          status: "unavailable",
          reason: failureReason(outcome.reason),
        };
      })
      .filter((source) => source.status !== "disabled");

    const matched = sources.filter((source) => source.status === "match");
    const clean = sources.filter((source) => source.status === "no_match");

    let status = "unavailable";
    if (matched.length > 0) status = "match";
    else if (clean.length > 0) status = "no_match";

    const result = {
      status,
      isListed: matched.length > 0,
      sources,
      checkedAt: new Date(now()).toISOString(),
      message:
        status === "match"
          ? "This address is reported by one or more threat lists."
          : status === "no_match"
            ? "No match was found in the lists that were checked. This does not guarantee the address is safe."
            : "No online threat list could be reached.",
    };

    // Unavailable results are not cached so the next request retries.
    if (status !== "unavailable") {
      if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
      cache.set(cacheKey, { at: now(), result });
    }

    return result;
  };
}
