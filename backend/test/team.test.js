import test from "node:test";
import assert from "node:assert/strict";
import {
  formatJoinCode,
  generateJoinCode,
  generateManagerKey,
  hashKey,
  keyMatches,
  normalizeJoinCode,
} from "../lib/team/codes.js";
import { summarizeResults } from "../lib/team/summary.js";
import { createMemoryStore } from "../lib/team/memoryStore.js";
import { createSupabaseStore } from "../lib/team/supabaseStore.js";
import { validateResult } from "../lib/team/routes.js";
import { createApp } from "../server.js";

const NOW = Date.parse("2026-11-16T12:00:00Z");
const daysAgo = (days) => new Date(NOW - days * 86400000).toISOString();

const row = (score, missed = [], extra = {}) => ({
  score,
  total: 8,
  language: "en",
  missed,
  created_at: daysAgo(1),
  ...extra,
});

test("join codes are 8 readable characters and always normalize back", () => {
  for (let i = 0; i < 200; i += 1) {
    const code = generateJoinCode();

    assert.match(code, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$/);
    assert.equal(normalizeJoinCode(formatJoinCode(code)), code);
    assert.equal(normalizeJoinCode(formatJoinCode(code).toLowerCase()), code);
  }

  assert.equal(normalizeJoinCode(" abcd efgh "), "ABCDEFGH");
  assert.equal(normalizeJoinCode("ABCD-EFG"), null);
  assert.equal(normalizeJoinCode("ABCD-EFG0"), null);
  assert.equal(normalizeJoinCode("ABCD-EFGI"), null);
  assert.equal(normalizeJoinCode(undefined), null);
});

test("manager keys are random, hashed, and checked safely", () => {
  const key = generateManagerKey();
  const other = generateManagerKey();

  assert.ok(key.startsWith("mk_") && key.length > 30);
  assert.notEqual(key, other);
  assert.equal(hashKey(key).length, 64);
  assert.ok(!hashKey(key).includes(key));
  assert.equal(keyMatches(key, hashKey(key)), true);
  assert.equal(keyMatches(other, hashKey(key)), false);
  assert.equal(keyMatches("", hashKey(key)), false);
  assert.equal(keyMatches(key, "not-hex"), false);
});

test("a result must be an honest 8-question round", () => {
  const good = { score: 6, total: 8, language: "ar", missed: ["parcel-fee", "giveaway"] };

  assert.deepEqual(validateResult(good), good);
  assert.equal(validateResult({ ...good, score: 9 }) , null);
  assert.equal(validateResult({ ...good, total: 10 }), null);
  assert.equal(validateResult({ ...good, language: "fr" }), null);
  assert.equal(validateResult({ ...good, missed: ["parcel-fee"] }), null);
  assert.equal(validateResult({ ...good, missed: ["parcel-fee", "parcel-fee"] }), null);
  assert.equal(validateResult({ ...good, missed: ["parcel-fee", "made-up"] }), null);
  assert.equal(validateResult({ ...good, score: "6" }), null);
  assert.equal(validateResult(null), null);
});

test("with fewer than 3 results only counts are shown", () => {
  const summary = summarizeResults([row(2, ["a"]), row(8)], NOW);

  assert.equal(summary.enoughData, false);
  assert.equal(summary.completions, 2);
  assert.equal("averagePercent" in summary, false);
  assert.equal("mostMissed" in summary, false);
});

test("summary numbers are calculated correctly", () => {
  const rows = [
    row(8, [], { language: "ar" }),
    row(6, ["parcel-fee", "giveaway"]),
    row(4, ["parcel-fee", "ceo-invoice", "giveaway", "remote-job"], { created_at: daysAgo(10) }),
    row(7, ["parcel-fee"], { created_at: daysAgo(40) }),
  ];

  const summary = summarizeResults(rows, NOW);

  assert.equal(summary.enoughData, true);
  assert.equal(summary.completions, 4);
  assert.equal(summary.completionsLast30Days, 3);
  assert.equal(summary.averagePercent, Math.round((100 * 25) / 32));
  assert.equal(summary.strongPercent, 75);
  assert.deepEqual(summary.languages, { en: 3, ar: 1 });
  assert.deepEqual(summary.mostMissed[0], { id: "parcel-fee", count: 3, percent: 75 });
  assert.equal(summary.mostMissed[1].id, "giveaway");
  assert.deepEqual(summary.weekly, [2, 1, 0, 0]);
});

async function withServer(teamStore, run, teamLimits = {}) {
  const app = createApp({
    config: { frontendOrigins: ["http://localhost:5173"] },
    checker: async () => ({ status: "no_match", sources: [] }),
    teamStore,
    teamLimits,
  });

  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  const send = (path, body, method = "POST") =>
    fetch(`${base}/api/teams${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

  try {
    await run(send);
  } finally {
    server.close();
  }
}

test("full team flow: create, join, submit, summary, delete", async () => {
  await withServer(createMemoryStore(), async (send) => {
    const created = await send("", { name: "  Al Noor Trading  " });
    const team = await created.json();

    assert.equal(created.status, 201);
    assert.equal(team.name, "Al Noor Trading");
    assert.match(team.joinCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.ok(team.managerKey.startsWith("mk_"));

    const info = await (await send(`/${team.joinCode}/info`, undefined, "GET")).json();

    assert.deepEqual(info, { name: "Al Noor Trading" });
    assert.equal((await send("/ZZZZ-ZZZZ/info", undefined, "GET")).status, 404);

    const rounds = [
      { score: 8, total: 8, language: "en", missed: [] },
      { score: 6, total: 8, language: "ar", missed: ["parcel-fee", "giveaway"] },
      { score: 5, total: 8, language: "en", missed: ["parcel-fee", "ceo-invoice", "remote-job"] },
    ];

    for (const round of rounds) {
      assert.equal((await send(`/${team.joinCode}/results`, round)).status, 201);
    }

    assert.equal(
      (await send(`/${team.joinCode}/results`, { ...rounds[0], score: 99 })).status,
      400
    );
    assert.equal((await send("/ZZZZ-ZZZZ/results", rounds[0])).status, 404);

    const access = { joinCode: team.joinCode, managerKey: team.managerKey };
    const summary = await (await send("/summary", access)).json();

    assert.equal(summary.name, "Al Noor Trading");
    assert.equal(summary.completions, 3);
    assert.equal(summary.enoughData, true);
    assert.equal(summary.mostMissed[0].id, "parcel-fee");
    assert.ok(!JSON.stringify(summary).includes(team.managerKey));

    assert.equal((await send("/summary", { ...access, managerKey: "mk_wrong" })).status, 401);
    assert.equal((await send("/summary", { ...access, joinCode: "ZZZZ-ZZZZ" })).status, 401);
    assert.equal((await send("/summary", { joinCode: team.joinCode })).status, 401);

    assert.equal((await send("/delete", { ...access, managerKey: "mk_wrong" })).status, 401);
    assert.equal((await send("/delete", access)).status, 200);
    assert.equal((await send("/summary", access)).status, 401);
    assert.equal((await send(`/${team.joinCode}/info`, undefined, "GET")).status, 404);
  });
});

test("team names are checked", async () => {
  await withServer(createMemoryStore(), async (send) => {
    assert.equal((await send("", { name: "x".repeat(61) })).status, 400);
    assert.equal((await send("", { name: 123 })).status, 400);

    const blank = await send("", {});

    assert.equal(blank.status, 201);
    assert.equal((await blank.json()).name, "");
  });
});

test("creating teams is rate limited", async () => {
  await withServer(
    createMemoryStore(),
    async (send) => {
      assert.equal((await send("", {})).status, 201);
      assert.equal((await send("", {})).status, 201);
      assert.equal((await send("", {})).status, 429);
    },
    { createLimit: 2 }
  );
});

test("without storage the team routes say so", async () => {
  await withServer(null, async (send) => {
    const response = await send("", {});

    assert.equal(response.status, 503);
    assert.ok((await response.json()).error.includes("not set up"));
  });
});

test("a storage failure returns a safe error", async () => {
  const broken = {
    ...createMemoryStore(),
    getTeamByCode: async () => {
      throw new Error("db down with secret details");
    },
  };

  const originalError = console.error;

  console.error = () => {};

  try {
    await withServer(broken, async (send) => {
      const response = await send("/summary", { joinCode: "ABCD-EFGH", managerKey: "mk_x" });
      const text = JSON.stringify(await response.json());

      assert.equal(response.status, 503);
      assert.ok(!text.includes("secret details"));
    });
  } finally {
    console.error = originalError;
  }
});

test("Supabase store talks to the right tables with the right headers", async () => {
  const calls = [];
  const teamId = "123e4567-e89b-42d3-a456-426614174000";

  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });

    if (options.method === "POST" && String(url).endsWith("/teams")) {
      return { ok: true, status: 201, json: async () => [{ id: teamId }] };
    }

    if (String(url).includes("/teams?join_code=")) {
      return {
        ok: true,
        status: 200,
        json: async () => [{ id: teamId, name: "N", manager_key_hash: "abc" }],
      };
    }

    if (String(url).includes("/quiz_results?team_id=")) {
      return { ok: true, status: 200, json: async () => [{ score: 5 }] };
    }

    return { ok: true, status: 204, json: async () => ({}) };
  };

  const store = createSupabaseStore({
    url: "https://example-project.supabase.co/",
    key: "sb_secret_abc",
    fetchImpl,
  });

  assert.deepEqual(await store.createTeam({ name: "N", joinCode: "ABCDEFGH", keyHash: "h" }), {
    id: teamId,
  });
  assert.deepEqual(await store.getTeamByCode("ABCDEFGH"), {
    id: teamId,
    name: "N",
    keyHash: "abc",
  });
  await store.addResult({ teamId, score: 5, total: 8, language: "en", missed: ["x"] });
  assert.equal((await store.getResults(teamId)).length, 1);
  await store.deleteTeam(teamId);

  assert.equal(calls[0].url, "https://example-project.supabase.co/rest/v1/teams");
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    join_code: "ABCDEFGH",
    name: "N",
    manager_key_hash: "h",
  });
  assert.equal(calls[0].options.headers.apikey, "sb_secret_abc");
  assert.equal(calls[0].options.headers.Authorization, undefined);
  assert.ok(calls[1].url.includes("join_code=eq.ABCDEFGH"));
  assert.deepEqual(JSON.parse(calls[2].options.body), {
    team_id: teamId,
    score: 5,
    total: 8,
    language: "en",
    missed: ["x"],
  });
  assert.ok(calls[3].url.includes(`team_id=eq.${teamId}`));
  assert.equal(calls[4].options.method, "DELETE");
  assert.ok(calls[4].url.endsWith(`/teams?id=eq.${teamId}`));

  // Older JWT-style keys are also sent as a bearer token.
  const legacy = createSupabaseStore({ url: "https://x.supabase.co", key: "eyJabc", fetchImpl });

  await legacy.getTeamByCode("ABCDEFGH");
  assert.equal(calls.at(-1).options.headers.Authorization, "Bearer eyJabc");
});

test("Supabase store reports duplicate codes and refuses unsafe ids", async () => {
  const conflict = createSupabaseStore({
    url: "https://x.supabase.co",
    key: "k",
    fetchImpl: async () => ({ ok: false, status: 409, json: async () => ({}) }),
  });

  await assert.rejects(
    () => conflict.createTeam({ name: "", joinCode: "ABCDEFGH", keyHash: "h" }),
    (error) => error.code === "CODE_TAKEN"
  );

  const calls = [];
  const store = createSupabaseStore({
    url: "https://x.supabase.co",
    key: "k",
    fetchImpl: async (url) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => [] };
    },
  });

  assert.equal(await store.getTeamByCode("abc&select=*"), null);
  assert.deepEqual(await store.getResults("1; drop table teams"), []);
  await store.deleteTeam("not-a-uuid");
  assert.equal(calls.length, 0);

  const failing = createSupabaseStore({
    url: "https://x.supabase.co",
    key: "k",
    fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({}) }),
  });

  await assert.rejects(() => failing.getTeamByCode("ABCDEFGH"), /Storage error 500/);
});
