import test from "node:test";
import assert from "node:assert/strict";
import { createChecker, sanitizeForLookup } from "../lib/checkUrl.js";
import { createApp, parseOrigins } from "../server.js";

const jsonResponse = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  text: async () => JSON.stringify(body),
});

const baseConfig = { safeBrowsingKey: "", webRiskKey: "", urlhausKey: "" };

test("credentials and fragments are removed before lookup", () => {
  assert.equal(
    sanitizeForLookup("https://user:secret@example.com/a?b=1#frag"),
    "https://example.com/a?b=1"
  );
});

test("one source matching makes the whole result a match", async () => {
  const check = createChecker({
    config: { ...baseConfig, urlhausKey: "k", webRiskKey: "k" },
    fetchImpl: async (endpoint) =>
      String(endpoint).includes("urlhaus")
        ? jsonResponse({ query_status: "ok", url_status: "online" })
        : jsonResponse({}),
  });

  const result = await check("http://evil.example/x.exe");

  assert.equal(result.status, "match");
  assert.equal(result.isListed, true);
  assert.equal(result.sources.find((s) => s.id === "urlhaus").status, "match");
  assert.equal(result.sources.find((s) => s.id === "webrisk").status, "no_match");
});

test("if every source fails the result is unavailable, not safe", async () => {
  const check = createChecker({
    config: { ...baseConfig, urlhausKey: "k", webRiskKey: "k" },
    fetchImpl: async () => {
      throw new Error("network down");
    },
  });

  const result = await check("http://fine.example/");

  assert.equal(result.status, "unavailable");
  assert.equal(result.isListed, false);
});

test("one failing source does not hide a match from another", async () => {
  const check = createChecker({
    config: { ...baseConfig, urlhausKey: "k", webRiskKey: "k" },
    fetchImpl: async (endpoint) => {
      if (String(endpoint).includes("urlhaus")) {
        return jsonResponse({ query_status: "ok" });
      }
      throw new Error("timeout");
    },
  });

  const result = await check("http://evil.example/x");

  assert.equal(result.status, "match");
});

test("results are cached, failures are not", async () => {
  let calls = 0;

  const check = createChecker({
    config: { ...baseConfig, urlhausKey: "k" },
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({ query_status: "no_results" });
    },
  });

  await check("http://fine.example/");
  await check("http://fine.example/#other-fragment");

  assert.equal(calls, 1);

  let failing = 0;

  const check2 = createChecker({
    config: { ...baseConfig, urlhausKey: "k" },
    fetchImpl: async () => {
      failing += 1;
      throw new Error("down");
    },
  });

  await check2("http://fine.example/");
  await check2("http://fine.example/");

  assert.equal(failing, 2);
});

test("API route validates input and returns the checker result", async () => {
  const config = { frontendOrigins: ["http://localhost:5173"], port: 0 };
  const app = createApp({
    config,
    checker: async (url) => ({ status: "no_match", echoed: url, sources: [] }),
  });

  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    const post = (body) =>
      fetch(`${base}/api/check-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

    assert.equal((await post({})).status, 400);
    assert.equal((await post({ url: "ftp://x.example" })).status, 400);
    assert.equal((await post({ url: "not a url" })).status, 400);
    assert.equal((await post({ url: "http://a.example/" + "x".repeat(3000) })).status, 400);

    const ok = await post({ url: "https://fine.example/page" });

    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).status, "no_match");
  } finally {
    server.close();
  }
});

test("allowed origins are parsed from a comma separated list", () => {
  assert.deepEqual(
    parseOrigins(" https://app.vercel.app/ , http://localhost:5173,, "),
    ["https://app.vercel.app", "http://localhost:5173"]
  );
});

test("CORS allows listed websites and not others", async () => {
  const app = createApp({
    config: {
      frontendOrigins: ["https://app.vercel.app", "http://localhost:5173"],
    },
    checker: async () => ({ status: "no_match", sources: [] }),
  });

  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    const ask = (origin) =>
      fetch(`${base}/api/health`, { headers: { Origin: origin } });

    assert.equal(
      (await ask("https://app.vercel.app")).headers.get("access-control-allow-origin"),
      "https://app.vercel.app"
    );
    assert.equal(
      (await ask("http://localhost:5173")).headers.get("access-control-allow-origin"),
      "http://localhost:5173"
    );
    assert.equal(
      (await ask("https://evil.example")).headers.get("access-control-allow-origin"),
      null
    );
  } finally {
    server.close();
  }
});
