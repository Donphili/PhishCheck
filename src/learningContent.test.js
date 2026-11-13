import test from "node:test";
import assert from "node:assert/strict";
import {
  afterIncident,
  buildRound,
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
