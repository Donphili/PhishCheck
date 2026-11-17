import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// No 0, 1, I, L or O, so codes are easy to read out loud and type.
const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 8;

export function generateJoinCode(randomFn = randomBytes) {
  let code = "";

  // Bytes at or above 248 are skipped so every letter is equally likely.
  while (code.length < CODE_LENGTH) {
    for (const byte of randomFn(16)) {
      if (byte < 248 && code.length < CODE_LENGTH) {
        code += ALPHABET[byte % ALPHABET.length];
      }
    }
  }

  return code;
}

export function normalizeJoinCode(input) {
  const code = String(input || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");

  if (code.length !== CODE_LENGTH) return null;
  if ([...code].some((letter) => !ALPHABET.includes(letter))) return null;

  return code;
}

export function formatJoinCode(code) {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

export function generateManagerKey() {
  return `mk_${randomBytes(24).toString("base64url")}`;
}

export function hashKey(key) {
  return createHash("sha256").update(String(key)).digest("hex");
}

export function keyMatches(key, storedHash) {
  try {
    const given = Buffer.from(hashKey(key), "hex");
    const stored = Buffer.from(String(storedHash), "hex");

    return given.length === stored.length && timingSafeEqual(given, stored);
  } catch {
    return false;
  }
}
