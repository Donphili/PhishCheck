// Small helpers for team training. They match the rules in the backend
// (backend/lib/team/codes.js) so codes typed by people are accepted.

const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

export function normalizeJoinCode(input) {
  const code = String(input || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");

  if (code.length !== 8) return "";
  if ([...code].some((letter) => !ALPHABET.includes(letter))) return "";

  return code;
}

export function formatJoinCode(code) {
  const clean = normalizeJoinCode(code);

  return clean ? `${clean.slice(0, 4)}-${clean.slice(4)}` : "";
}

export function buildStaffLink(origin, joinCode) {
  return `${String(origin).replace(/\/+$/, "")}/?team=${formatJoinCode(joinCode)}`;
}

// Reads ?team=ABCD-EFGH from the address bar. Anything else is ignored.
export function teamFromSearch(search) {
  try {
    return normalizeJoinCode(new URLSearchParams(search).get("team"));
  } catch {
    return "";
  }
}
