import test from "node:test";
import assert from "node:assert/strict";
import {
  afterIncident,
  buildRound,
  getAfterIncident,
  getVerifySteps,
  localizeQuestion,
  quizQuestions,
  ROUND_SIZE,
  scoreMessage,
  shuffle,
  verifySteps,
} from "./learningContent.js";
import { analyzeMessage, analyzeUrl } from "./securityEngine.js";

// Small repeatable random generator so shuffle tests are deterministic.
function seeded(seed) {
  let state = seed;

  return () => {
    state = (state * 1664525 + 1013904223) % 4294967296;
    return state / 4294967296;
  };
}

test("every quiz question is complete and ids are unique", () => {
  const ids = new Set();

  for (const q of quizQuestions) {
    assert.ok(!ids.has(q.id), `duplicate id ${q.id}`);
    ids.add(q.id);

    assert.ok(q.channel && q.content && q.explanation && q.action, q.id);
    assert.equal(typeof q.isScam, "boolean", q.id);
    assert.ok(["message", "link", "none"].includes(q.kind), q.id);
    assert.ok(Array.isArray(q.redFlags), q.id);

    // Scams must teach at least one warning sign, genuine ones none.
    assert.equal(q.redFlags.length > 0, q.isScam, q.id);
  }
});

test("the quiz has enough of both kinds for a balanced round", () => {
  const genuine = quizQuestions.filter((q) => !q.isScam).length;
  const scams = quizQuestions.filter((q) => q.isScam).length;

  assert.ok(genuine >= 3);
  assert.ok(scams >= ROUND_SIZE - 3);
});

test("PhishCheck agrees with the lessons it teaches", () => {
  for (const q of quizQuestions.filter((item) => item.kind !== "none")) {
    const result =
      q.kind === "link" ? analyzeUrl(q.content) : analyzeMessage(q.content);

    if (q.isScam) {
      assert.ok(result.score >= 30, `${q.id} should be Moderate or higher`);
    } else {
      assert.ok(result.score < 30, `${q.id} should stay Low`);
    }
  }
});

test("a round has 8 unique questions with genuine ones mixed in", () => {
  for (let seed = 1; seed <= 20; seed += 1) {
    const round = buildRound(seeded(seed));

    assert.equal(round.length, ROUND_SIZE);
    assert.equal(new Set(round.map((q) => q.id)).size, ROUND_SIZE);
    assert.equal(round.filter((q) => !q.isScam).length, 3);
  }
});

test("shuffle keeps every item and does not change the input", () => {
  const input = [1, 2, 3, 4, 5, 6];
  const output = shuffle(input, seeded(7));

  assert.deepEqual([...output].sort(), [...input].sort());
  assert.deepEqual(input, [1, 2, 3, 4, 5, 6]);
});

test("score messages cover every band", () => {
  assert.ok(scoreMessage(8, 8).startsWith("Perfect"));
  assert.ok(scoreMessage(6, 8).startsWith("Strong"));
  assert.ok(scoreMessage(4, 8).startsWith("A decent"));
  assert.ok(scoreMessage(1, 8).startsWith("Do not worry"));
});

test("checklist and incident steps are well formed", () => {
  assert.equal(new Set(verifySteps.map((s) => s.id)).size, verifySteps.length);
  assert.equal(
    new Set(afterIncident.map((s) => s.id)).size,
    afterIncident.length
  );

  for (const step of verifySteps) assert.ok(step.title && step.detail);

  for (const item of afterIncident) {
    assert.ok(item.steps.length >= 3, item.id);
  }
});

const hasArabic = (text) => /[\u0600-\u06FF]/.test(text);

test("every scenario has complete Arabic text with the same answer", () => {
  for (const base of quizQuestions) {
    const ar = localizeQuestion(base, "ar");

    // Which tool it opens and whether it is a scam never depends on language.
    assert.equal(ar.id, base.id);
    assert.equal(ar.isScam, base.isScam);
    assert.equal(ar.kind, base.kind);

    assert.ok(hasArabic(ar.channel), `${base.id} channel`);
    assert.ok(hasArabic(ar.explanation), `${base.id} explanation`);
    assert.ok(hasArabic(ar.action), `${base.id} action`);
    assert.ok(Array.isArray(ar.redFlags), base.id);
    assert.equal(ar.redFlags.length > 0, base.isScam, base.id);

    for (const flag of ar.redFlags) assert.ok(hasArabic(flag), base.id);

    // Context only exists in Arabic when it exists in English.
    assert.equal(Boolean(ar.context), Boolean(base.context), base.id);

    if (base.kind === "link") {
      assert.equal(ar.content, base.content, `${base.id} keeps the same address`);
    } else {
      assert.ok(hasArabic(ar.content), `${base.id} content`);
    }
  }
});

test("PhishCheck judges the Arabic scenarios the same way", () => {
  for (const base of quizQuestions.filter((q) => q.kind !== "none")) {
    const q = localizeQuestion(base, "ar");
    const result =
      q.kind === "link" ? analyzeUrl(q.content) : analyzeMessage(q.content);

    if (q.isScam) {
      assert.ok(result.score >= 30, `${q.id} (Arabic) should be Moderate or higher`);
    } else {
      assert.ok(result.score < 30, `${q.id} (Arabic) should stay Low`);
    }
  }
});

test("Arabic checklist and incident steps match the English ones", () => {
  assert.deepEqual(
    getVerifySteps("ar").map((s) => s.id),
    getVerifySteps("en").map((s) => s.id)
  );
  assert.deepEqual(
    getAfterIncident("ar").map((s) => s.id),
    getAfterIncident("en").map((s) => s.id)
  );

  for (const step of getVerifySteps("ar")) {
    assert.ok(hasArabic(step.title) && hasArabic(step.detail), step.id);
  }

  for (const item of getAfterIncident("ar")) {
    assert.ok(hasArabic(item.title), item.id);
    assert.ok(item.steps.length >= 3, item.id);
    assert.ok(item.steps.every(hasArabic), item.id);
  }
});

test("English helpers are unchanged and Arabic score messages exist", () => {
  assert.equal(getVerifySteps("en"), verifySteps);
  assert.equal(getAfterIncident("en"), afterIncident);
  assert.equal(localizeQuestion(quizQuestions[0], "en"), quizQuestions[0]);

  for (const [correct, total] of [[8, 8], [6, 8], [4, 8], [1, 8]]) {
    assert.ok(hasArabic(scoreMessage(correct, total, "ar")));
  }
});
