import test from "node:test";
import assert from "node:assert/strict";
import { analyzeUrl } from "./securityEngine.js";
import { applyLinkCheck } from "./linkCheck.js";

const base = () => analyzeUrl("https://fine.example/");

test("a listed address becomes High risk and names the source", () => {
  const result = applyLinkCheck(base(), {
    status: "match",
    sources: [
      { name: "Google Safe Browsing", status: "match", threats: ["phishing or social engineering"] },
      { name: "URLhaus (abuse.ch)", status: "no_match" },
    ],
  });

  assert.equal(result.riskLevel, "High");
  assert.ok(result.indicators.some((i) => i.label === "Reported by Google Safe Browsing"));
  assert.ok(result.indicators[0].explanation.includes("suspected"));
});

test("a clean result keeps the risk level and says it is not a guarantee", () => {
  const result = applyLinkCheck(base(), {
    status: "no_match",
    sources: [
      { name: "Google Safe Browsing", status: "no_match" },
      { name: "URLhaus (abuse.ch)", status: "unavailable" },
    ],
  });

  assert.equal(result.riskLevel, "Low");
  assert.ok(result.safetyNote.includes("Google Safe Browsing"));
  assert.ok(result.safetyNote.includes("could not be reached"));
  assert.ok(result.safetyNote.includes("does not guarantee"));
});

test("when nothing could be reached the result says so", () => {
  const result = applyLinkCheck(base(), {
    status: "unavailable",
    sources: [{ name: "Google Safe Browsing", status: "unavailable" }],
  });

  assert.ok(result.safetyNote.includes("could not be reached"));
});

test("no backend answer adds a note and keeps the local result", () => {
  const analysis = base();
  const result = applyLinkCheck(analysis, null);

  assert.equal(result.score, analysis.score);
  assert.equal(result.riskLevel, analysis.riskLevel);
  assert.ok(result.safetyNote.includes("could not be reached"));
});
