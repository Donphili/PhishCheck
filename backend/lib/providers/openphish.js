import { canonicalizeUrl } from "../canonicalize.js";

export const OPENPHISH_NAME = "OpenPhish Community Feed";

const DEFAULT_FEED =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const REFRESH_MS = 12 * 60 * 60 * 1000;
const RETRY_MS = 60 * 1000;

function keyFor(url) {
  const { host, path } = canonicalizeUrl(url);
  const cleanPath = path.length > 1 ? path.replace(/\/+$/, "") : path;

  return `${host}${cleanPath}`;
}

export function parseFeed(text) {
  const keys = new Set();

  for (const line of String(text).split(/\r?\n/)) {
    const entry = line.trim();

    if (/^https?:\/\//i.test(entry)) keys.add(keyFor(entry));
  }

  return keys;
}

// The community feed is licensed for NON-COMMERCIAL use only. It is switched
// off unless ENABLE_OPENPHISH=true. Stop using it if PhishCheck starts selling
// anything, or buy an OpenPhish licence.
export class OpenPhishFeed {
  constructor({
    feedUrl = DEFAULT_FEED,
    fetchImpl = fetch,
    refreshMs = REFRESH_MS,
    retryMs = RETRY_MS,
  } = {}) {
    this.feedUrl = feedUrl;
    this.fetchImpl = fetchImpl;
    this.refreshMs = refreshMs;
    this.retryMs = retryMs;
    this.keys = new Set();
    this.loadedAt = null;
    this.timer = null;
    this.stopped = false;
  }

  async refresh() {
    const response = await this.fetchImpl(this.feedUrl, {
      signal: AbortSignal.timeout(20000),
    });

    if (!response.ok) throw new Error(`Feed download failed (${response.status})`);

    this.keys = parseFeed(await response.text());
    this.loadedAt = Date.now();
  }

  // Loads the feed now, then every 12 hours. If a download fails it tries
  // again after a minute instead of leaving the feed empty for 12 hours.
  start() {
    this.stopped = false;

    const attempt = async () => {
      let delay = this.refreshMs;

      try {
        await this.refresh();
      } catch (error) {
        const code = error?.cause?.code ? ` (${error.cause.code})` : "";

        console.error(
          `OpenPhish feed could not be loaded: ${error?.message}${code}. Retrying in ${Math.round(this.retryMs / 1000)} seconds.`
        );
        delay = this.retryMs;
      }

      if (this.stopped) return;

      this.timer = setTimeout(attempt, delay);
      this.timer.unref?.();
    };

    return attempt();
  }

  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
  }

  async check(url) {
    const stale =
      !this.loadedAt || Date.now() - this.loadedAt > this.refreshMs * 2;

    if (stale) {
      return {
        id: "openphish",
        name: OPENPHISH_NAME,
        status: "unavailable",
        reason: this.loadedAt ? "feed_out_of_date" : "feed_not_loaded",
      };
    }

    return this.keys.has(keyFor(url))
      ? { id: "openphish", name: OPENPHISH_NAME, status: "match", threats: ["phishing"] }
      : { id: "openphish", name: OPENPHISH_NAME, status: "no_match", threats: [] };
  }
}
