import { checkSafeBrowsing } from "./providers/safeBrowsing.js";
import { checkWebRisk } from "./providers/webRisk.js";
import { checkUrlhaus } from "./providers/urlhaus.js";
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

export function createChecker({ config, openPhish = null, fetchImpl = fetch, now = Date.now }) {
  const cache = new Map();

  const providers = [
    (url) => checkSafeBrowsing(url, { apiKey: config.safeBrowsingKey, fetchImpl }),
    (url) => checkWebRisk(url, { apiKey: config.webRiskKey, fetchImpl }),
    (url) => checkUrlhaus(url, { authKey: config.urlhausKey, fetchImpl }),
    (url) =>
      openPhish
        ? openPhish.check(url)
        : { id: "openphish", name: "OpenPhish Community Feed", status: "disabled" },
  ];

  return async function checkUrl(rawUrl) {
    const url = sanitizeForLookup(rawUrl);
    const cacheKey = canonicalizeUrl(url).url;
    const cached = cache.get(cacheKey);

    if (cached && now() - cached.at < CACHE_TTL_MS) return cached.result;

    const settled = await Promise.allSettled(providers.map((run) => run(url)));

    const sources = settled
      .map((outcome, index) => {
        if (outcome.status === "fulfilled") return outcome.value;

        console.error("Provider error:", outcome.reason?.name || "unknown");

        return { id: `provider-${index}`, name: "Unknown source", status: "unavailable" };
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
