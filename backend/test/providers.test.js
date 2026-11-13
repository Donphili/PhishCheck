import test from "node:test";
import assert from "node:assert/strict";
import { urlExpressions, sha256Latin1 } from "../lib/canonicalize.js";
import { checkSafeBrowsing } from "../lib/providers/safeBrowsing.js";
import { checkWebRisk } from "../lib/providers/webRisk.js";
import { checkUrlhaus } from "../lib/providers/urlhaus.js";
import { OpenPhishFeed, parseFeed } from "../lib/providers/openphish.js";

const jsonResponse = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
});

test("Safe Browsing: matching full hash is reported", async () => {
  const target = "evil.example/login";
  const hash = sha256Latin1(target);

  let requested;

  const result = await checkSafeBrowsing("http://evil.example/login", {
    apiKey: "k",
    fetchImpl: async (endpoint, options) => {
      requested = { endpoint: String(endpoint), headers: options.headers };

      return jsonResponse({
        fullHashes: [
          {
            fullHash: hash.toString("base64"),
            fullHashDetails: [{ threatType: "SOCIAL_ENGINEERING" }],
          },
        ],
      });
    },
  });

  assert.equal(result.status, "match");
  assert.deepEqual(result.threats, ["phishing or social engineering"]);
  assert.ok(requested.endpoint.includes("hashPrefixes="));
  assert.equal(requested.headers["x-goog-api-key"], "k");
  assert.ok(!requested.endpoint.includes("key="), "key must not be in the URL");

  const sentPrefixes = new URL(requested.endpoint).searchParams.getAll("hashPrefixes");
  const expected = urlExpressions("http://evil.example/login").map((value) =>
    sha256Latin1(value).subarray(0, 4).toString("base64url")
  );

  assert.ok(sentPrefixes.every((prefix) => expected.includes(prefix)));
  assert.ok(sentPrefixes.length <= 30);
});

test("Safe Browsing: prefix collision with a different full hash is ignored", async () => {
  const result = await checkSafeBrowsing("http://fine.example/", {
    apiKey: "k",
    fetchImpl: async () =>
      jsonResponse({
        fullHashes: [
          {
            fullHash: sha256Latin1("totally-different.example/").toString("base64"),
            fullHashDetails: [{ threatType: "MALWARE" }],
          },
        ],
      }),
  });

  assert.equal(result.status, "no_match");
});

test("Safe Browsing: canary and unknown threat types are ignored", async () => {
  const hash = sha256Latin1("evil.example/").toString("base64");

  const result = await checkSafeBrowsing("http://evil.example/", {
    apiKey: "k",
    fetchImpl: async () =>
      jsonResponse({
        fullHashes: [
          {
            fullHash: hash,
            fullHashDetails: [
              { threatType: "MALWARE", attributes: ["CANARY"] },
              { threatType: "SOMETHING_NEW" },
            ],
          },
        ],
      }),
  });

  assert.equal(result.status, "no_match");
});

test("Safe Browsing: empty response means no match, errors mean unavailable", async () => {
  const empty = await checkSafeBrowsing("http://fine.example/", {
    apiKey: "k",
    fetchImpl: async () => jsonResponse({}),
  });
  assert.equal(empty.status, "no_match");

  const failed = await checkSafeBrowsing("http://fine.example/", {
    apiKey: "k",
    fetchImpl: async () => jsonResponse({}, 403),
  });
  assert.equal(failed.status, "unavailable");

  const off = await checkSafeBrowsing("http://fine.example/", { apiKey: "" });
  assert.equal(off.status, "disabled");
});

test("Web Risk: match, no match and failure", async () => {
  const hit = await checkWebRisk("http://evil.example/", {
    apiKey: "k",
    fetchImpl: async (endpoint, options) => {
      assert.equal(options.headers["x-goog-api-key"], "k");
      return jsonResponse({ threat: { threatTypes: ["MALWARE"] } });
    },
  });
  assert.equal(hit.status, "match");
  assert.deepEqual(hit.threats, ["malware"]);

  const clean = await checkWebRisk("http://fine.example/", {
    apiKey: "k",
    fetchImpl: async () => jsonResponse({}),
  });
  assert.equal(clean.status, "no_match");

  const failed = await checkWebRisk("http://fine.example/", {
    apiKey: "k",
    fetchImpl: async () => jsonResponse({}, 403),
  });
  assert.equal(failed.status, "unavailable");
});

test("URLhaus: ok, no_results, auth failure", async () => {
  const hit = await checkUrlhaus("http://evil.example/x.exe", {
    authKey: "k",
    fetchImpl: async (endpoint, options) => {
      assert.equal(options.headers["Auth-Key"], "k");
      assert.ok(options.body.startsWith("url="));
      return jsonResponse({ query_status: "ok", url_status: "online" });
    },
  });
  assert.equal(hit.status, "match");

  const clean = await checkUrlhaus("http://fine.example/", {
    authKey: "k",
    fetchImpl: async () => jsonResponse({ query_status: "no_results" }),
  });
  assert.equal(clean.status, "no_match");

  const denied = await checkUrlhaus("http://fine.example/", {
    authKey: "bad",
    fetchImpl: async () => jsonResponse({}, 403),
  });
  assert.equal(denied.status, "unavailable");
});

test("OpenPhish feed: parses, matches host and path, ignores queries", async () => {
  const keys = parseFeed(
    "http://scam.example/login/\nhttps://Other.pages.dev/\n# comment\n\nnot-a-url"
  );

  assert.equal(keys.size, 2);

  const feed = new OpenPhishFeed({
    fetchImpl: async () => jsonResponse("http://scam.example/login\nhttps://other.pages.dev/"),
  });

  assert.equal((await feed.check("http://scam.example/login")).status, "unavailable");

  await feed.refresh();

  assert.equal((await feed.check("https://scam.example/login/?utm=1")).status, "match");
  assert.equal((await feed.check("https://OTHER.pages.dev/")).status, "match");
  assert.equal((await feed.check("https://scam.example/other")).status, "no_match");
});
