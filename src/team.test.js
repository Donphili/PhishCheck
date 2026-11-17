import test from "node:test";
import assert from "node:assert/strict";
import { QUIZ_IDS, QUIZ_TOTAL } from "../backend/lib/team/ids.js";
import {
  generateJoinCode,
  normalizeJoinCode as backendNormalize,
} from "../backend/lib/team/codes.js";
import { quizQuestions, ROUND_SIZE } from "./learningContent.js";
import {
  buildStaffLink,
  formatJoinCode,
  normalizeJoinCode,
  teamFromSearch,
} from "./teamUtils.js";

test("the server and the quiz agree on the scenario list and round size", () => {
  assert.deepEqual(
    [...QUIZ_IDS].sort(),
    quizQuestions.map((question) => question.id).sort()
  );
  assert.equal(QUIZ_TOTAL, ROUND_SIZE);
});

test("every scenario has a readable topic for the manager's results", () => {
  for (const question of quizQuestions) {
    assert.ok(question.topic && question.topic.length > 3, question.id);
  }
});

test("team codes are handled the same way in the app and on the server", () => {
  for (let i = 0; i < 100; i += 1) {
    const code = generateJoinCode();

    assert.equal(normalizeJoinCode(code), backendNormalize(code));
    assert.equal(normalizeJoinCode(formatJoinCode(code).toLowerCase()), code);
  }

  assert.equal(normalizeJoinCode("abcd efgh"), "ABCDEFGH");
  assert.equal(normalizeJoinCode("ABCD-EFG0"), "");
  assert.equal(normalizeJoinCode(null), "");
  assert.equal(formatJoinCode("ABCDEFGH"), "ABCD-EFGH");
  assert.equal(formatJoinCode("nope"), "");
});

test("staff links are built and read back correctly", () => {
  const link = buildStaffLink("https://phish-check-nine.vercel.app/", "ABCDEFGH");

  assert.equal(link, "https://phish-check-nine.vercel.app/?team=ABCD-EFGH");
  assert.equal(teamFromSearch(new URL(link).search), "ABCDEFGH");
  assert.equal(teamFromSearch("?team=<script>"), "");
  assert.equal(teamFromSearch("?other=1"), "");
  assert.equal(teamFromSearch(""), "");
});
