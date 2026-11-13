import test from "node:test";
import assert from "node:assert/strict";
import { analyzeUrl, analyzeMessage } from "./securityEngine.js";

const url = (input) => analyzeUrl(input);
const msg = (input) => analyzeMessage(input);

test("official brand domains and country sites are not flagged", () => {
  for (const address of [
    "https://www.google.com/",
    "https://www.google.com.kw/search?q=x",
    "https://www.amazon.ae/",
    "https://fonts.googleapis.com/css",
    "https://login.microsoftonline.com/",
  ]) {
    assert.equal(url(address).riskLevel, "Low", address);
    assert.ok(url(address).score < 10, address);
  }
});

test("brand name inside another word is not flagged", () => {
  assert.equal(url("https://pineapple.com").score, 0);
});

test("lookalike and embedded-domain tricks are caught", () => {
  assert.notEqual(url("https://paypa1-secure.example/login").riskLevel, "Low");
  assert.equal(
    url("https://www.paypal.com.evil.example/login").riskLevel,
    "High"
  );
  assert.notEqual(url("https://www.google.com.kw.evil.example/").riskLevel, "Low");
});

test("a single high-severity signal is never reported as Low", () => {
  assert.notEqual(url("https://google.com@evil.example/").riskLevel, "Low");
  assert.notEqual(url("http://203.0.113.9/").riskLevel, "Low");
});

test("invalid URLs return an error", () => {
  assert.ok(url("").error);
  assert.ok(url("ftp://example.com").error);
  assert.ok(url("has spaces.com").error);
});

test("credential request is caught even with a warning sentence added", () => {
  const result = msg(
    "Warning: never share your password with strangers. Reply with your password and OTP now."
  );
  assert.ok(
    result.indicators.some((i) =>
      i.label.startsWith("Direct request for passwords")
    )
  );
  assert.notEqual(result.riskLevel, "Low");
});

test("a plain warning is not treated as a request", () => {
  const result = msg("Never share your OTP with anyone, including bank staff.");
  assert.ok(
    !result.indicators.some((i) =>
      i.label.startsWith("Direct request for passwords")
    )
  );
});

test("delivery fee scam with a link is at least Moderate", () => {
  const result = msg(
    "Your parcel is held at customs. Pay the 1.5 KD fee here: http://kw-post.example/pay"
  );
  assert.notEqual(result.riskLevel, "Low");
});

test("Arabic credential request is detected", () => {
  const result = msg("تم إيقاف حسابك البنكي، يرجى إدخال رمز التحقق فوراً");
  assert.equal(result.riskLevel, "High");
});

test("links inside a message are analyzed", () => {
  const result = msg("Check this: https://www.paypal.com.evil.example/login");
  assert.ok(result.indicators.some((i) => i.label.startsWith("Link in message")));
});

test("empty and oversized messages return an error", () => {
  assert.ok(msg("").error);
  assert.ok(msg("a".repeat(10001)).error);
});
