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

test("ordinary messages are not flagged", () => {
  const benign = [
    "Hi, are we still meeting at 6 today? I'll bring the documents.",
    "Your OTP for login is 551203. Do not share it with anyone.",
    "Please note our bank details have not changed. Invoice 2291 is attached.",
    "The new account manager will contact you next week to introduce herself.",
    "Delivery code: 4821. Please give it to the driver when he arrives.",
    "I'll pay you back tomorrow for the lunch, thanks for covering me.",
    "Earn your degree online with flexible schedules. Enrollment is open.",
    "Don't call me before 9, I'm sleeping. Text me instead.",
  ];

  for (const text of benign) {
    assert.ok(msg(text).score < 30, text);
  }
});

test("asking you to read out a code is caught", () => {
  const result = msg(
    "We blocked a transfer. Please read us the code we just sent to your phone."
  );

  assert.ok(
    result.indicators.some((i) => i.label.startsWith("Direct request for passwords"))
  );
});

test("job, bank-detail and new-number scams are caught", () => {
  assert.ok(
    msg("Earn 40 KD per day just by liking videos. No experience needed.").score >= 25
  );
  assert.ok(
    msg("Use the new bank details in the file. Do not call me.").score >= 30
  );
  assert.ok(
    msg("I lost my phone, new number. Transfer 50 KD to this account please.").score >= 30
  );
});

test("ordinary Arabic messages are not flagged", () => {
  const benign = [
    "هل ما زلنا على موعدنا الساعة 6 اليوم؟ سأحضر المستندات.",
    "رمز التحقق الخاص بك هو 551203. لا تشارك هذا الرمز مع أي شخص.",
    "تم إيداع الراتب في حسابك المنتهي بـ 4410.",
    "سيصل طردك بين الساعة 2 و 5 مساءً. تابعه من تطبيق شركة التوصيل.",
    "يمكنك فتح حساب جديد من خلال التطبيق في أي وقت.",
    "لا تتصل بي قبل التاسعة، سأكون نائماً. راسلني بدلاً من ذلك.",
    "تذكرة رحلتك إلى دبي مؤكدة. يفتح تسجيل الوصول قبل 24 ساعة من الإقلاع.",
  ];

  for (const text of benign) {
    assert.ok(msg(text).score < 30, text);
  }
});

test("Arabic scams are caught", () => {
  assert.ok(
    msg("لإلغاء التحويل، اقرأ لنا الرمز الذي أرسلناه للتو إلى هاتفك.").score >= 30
  );
  assert.ok(
    msg("مبروك! ربحت جائزة. أرسل بيانات بطاقتك هنا.").score >= 30
  );
  assert.ok(
    msg("لديك مخالفة مرورية غير مدفوعة. ادفع خلال 24 ساعة: http://traffic-fines-pay.example").score >= 30
  );
});
