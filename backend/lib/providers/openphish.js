import { canonicalizeUrl } from "../canonicalize.js";

export const OPENPHISH_NAME = "OpenPhish Community Feed";

const DEFAULT_FEED =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const REFRESH_MS = 12 * 60 * 60 * 1000;

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
  constructor({ feedUrl = DEFAULT_FEED, fetchImpl = fetch } = {}) {
    this.feedUrl = feedUrl;
    this.fetchImpl = fetchImpl;
    this.keys = new Set();
    this.loadedAt = null;
    this.timer = null;
  }

  async refresh() {
    const response = await this.fetchImpl(this.feedUrl, {
      signal: AbortSignal.timeout(20000),
    });

    if (!response.ok) throw new Error(`Feed download failed (${response.status})`);

    this.keys = parseFeed(await response.text());
    this.loadedAt = Date.now();
  }

  start() {
    this.refresh().catch((error) =>
      console.error("OpenPhish feed could not be loaded:", error.message)
    );

    this.timer = setInterval(() => {
      this.refresh().catch((error) =>
        console.error("OpenPhish feed refresh failed:", error.message)
      );
    }, REFRESH_MS);

    this.timer.unref?.();
  }

  async check(url) {
    const stale = !this.loadedAt || Date.now() - this.loadedAt > REFRESH_MS * 2;

    if (stale) return { id: "openphish", name: OPENPHISH_NAME, status: "unavailable" };

    return this.keys.has(keyFor(url))
      ? { id: "openphish", name: OPENPHISH_NAME, status: "match", threats: ["phishing"] }
      : { id: "openphish", name: OPENPHISH_NAME, status: "no_match", threats: [] };
  }
}
