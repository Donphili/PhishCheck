import test from "node:test";
import assert from "node:assert/strict";
import {
  buildExport,
  describeImport,
  mergeImport,
  sanitizeItem,
} from "./historyTransfer.js";

const item = (n, extra = {}) => ({
  id: `id-${n}`,
  type: "URL",
  url: `http://site${n}.example/`,
  risk: "Low",
  score: 10,
  scannedAt: new Date(Date.UTC(2026, 10, n + 1)).toISOString(),
  indicators: [
    { label: "Test", points: 8, severity: "low", explanation: "Because." },
  ],
  submittedContent: `http://site${n}.example/`,
  normalizedUrl: `http://site${n}.example/`,
  safetyNote: "Note",
  ...extra,
});

const fileOf = (items) => buildExport(items, new Date("2026-11-14T10:00:00Z")).content;

test("export has a dated file name and the right wrapper", () => {
  const { fileName, content } = buildExport([item(1)], new Date("2026-11-14T10:00:00Z"));
  const data = JSON.parse(content);

  assert.equal(fileName, "phishcheck-history-2026-11-14.json");
  assert.equal(data.format, "phishcheck-history");
  assert.equal(data.version, 1);
  assert.equal(data.items.length, 1);
});

test("export then import into an empty history keeps everything", () => {
  const original = [item(3), item(2), item(1)];
  const outcome = mergeImport(fileOf(original), []);

  assert.equal(outcome.added, 3);
  assert.deepEqual(
    outcome.items.map((i) => i.id),
    ["id-3", "id-2", "id-1"]
  );
  assert.deepEqual(outcome.items[0].indicators, original[0].indicators);
});

test("importing the same file twice adds nothing the second time", () => {
  const file = fileOf([item(1), item(2)]);
  const first = mergeImport(file, []);
  const second = mergeImport(file, first.items);

  assert.equal(second.added, 0);
  assert.equal(second.duplicates, 2);
  assert.equal(second.items.length, 2);
});

test("a phone and a laptop history merge, newest first", () => {
  const laptop = [item(5), item(3), item(1)];
  const phone = [item(4, { id: "phone-4" })];
  const outcome = mergeImport(fileOf(phone), laptop);

  assert.equal(outcome.added, 1);
  assert.deepEqual(
    outcome.items.map((i) => i.url),
    [5, 4, 3, 1].map((n) => `http://site${n}.example/`)
  );
});

test("the history cap keeps the newest scans and says what was left out", () => {
  const existing = Array.from({ length: 19 }, (_, n) => item(n + 10));
  const incoming = [item(1), item(2), item(29), item(30), item(31)];
  const outcome = mergeImport(fileOf(incoming), existing, { max: 20 });

  assert.equal(outcome.items.length, 20);
  assert.equal(outcome.items[0].url, "http://site31.example/");
  assert.equal(outcome.added + outcome.trimmed, 5);
  assert.ok(outcome.trimmed >= 1);
  assert.ok(describeImport(outcome, 20).includes("newest 20"));
});

test("colliding ids from another device get new ids", () => {
  const laptop = [item(1)];
  const phone = [item(2, { id: "id-1" })];
  const outcome = mergeImport(fileOf(phone), laptop);

  assert.equal(outcome.items.length, 2);
  assert.equal(new Set(outcome.items.map((i) => i.id)).size, 2);
});

test("files that are not PhishCheck history are rejected", () => {
  assert.ok(mergeImport("", []).error);
  assert.ok(mergeImport("not json", []).error);
  assert.ok(mergeImport("[]", []).error);
  assert.ok(mergeImport(JSON.stringify({ format: "other", items: [] }), []).error);
  assert.ok(
    mergeImport(JSON.stringify({ format: "phishcheck-history", version: 99, items: [] }), [])
      .error.includes("newer version")
  );
  assert.ok(mergeImport("x".repeat(1_000_001), []).error);
});

test("hostile or damaged entries are cleaned or skipped", () => {
  const hostile = {
    format: "phishcheck-history",
    version: 1,
    items: [
      item(1, { risk: "Catastrophic" }),
      item(2, { scannedAt: "not a date" }),
      item(3, { score: "abc" }),
      { __proto__: { polluted: true }, ...item(4), onclick: "alert(1)", extra: "x" },
      item(5, { url: "http://long.example/" + "a".repeat(5000) }),
      item(6, { id: "<script>alert(1)</script>" }),
      item(7, { indicators: [{ label: "L", severity: "<b>", points: 9999 }, "bad", null] }),
      null,
      "text",
    ],
  };

  const outcome = mergeImport(JSON.stringify(hostile), []);
  const byUrl = (n) => outcome.items.find((i) => i.url.startsWith(`http://site${n}.`));

  assert.equal(outcome.invalid, 5);
  assert.ok(byUrl(4));
  assert.equal("onclick" in byUrl(4), false);
  assert.equal("extra" in byUrl(4), false);
  assert.equal({}.polluted, undefined);
  assert.ok(outcome.items.every((i) => i.url.length <= 2048));
  assert.ok(/^[\w.-]+$/.test(byUrl(6).id));

  const indicators = byUrl(7).indicators;

  assert.equal(indicators.length, 1);
  assert.equal(indicators[0].severity, "low");
  assert.equal(indicators[0].points, 100);
});

test("message text is cut to the short preview", () => {
  const message = item(1, {
    type: "MESSAGE",
    url: "anything",
    submittedContent: "secret ".repeat(100),
  });

  const clean = sanitizeItem(message, { previewLength: 120, makeId: () => "n" });

  assert.equal(clean.url, "Message analysis");
  assert.equal(clean.submittedContent.length, 120);
});

test("import summaries read naturally", () => {
  assert.equal(
    describeImport({ added: 1, duplicates: 0, invalid: 0, trimmed: 0 }),
    "Imported 1 scan."
  );
  assert.equal(
    describeImport({ added: 3, duplicates: 2, invalid: 1, trimmed: 0 }),
    "Imported 3 scans. 2 already in your history. 1 could not be read and were skipped."
  );
});
