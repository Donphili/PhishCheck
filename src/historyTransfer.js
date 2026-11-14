// Export and import of the scan history, so it can move between devices.
// Imported files are treated as untrusted: every field is checked, cut to a
// safe length and copied into a fresh object, and anything unexpected is
// dropped.

export const EXPORT_FORMAT = "phishcheck-history";
export const EXPORT_VERSION = 1;

const MAX_FILE_CHARS = 1_000_000;
const MAX_ITEMS_READ = 200;
const MAX_INDICATORS = 40;

const RISKS = new Set(["Low", "Moderate", "High"]);
const SEVERITIES = new Set(["low", "medium", "high"]);
const TYPES = new Set(["URL", "MESSAGE"]);

const cut = (value, max) => (typeof value === "string" ? value.slice(0, max) : "");

function cleanIndicators(value) {
  if (!Array.isArray(value)) return [];

  return value.slice(0, MAX_INDICATORS).flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];

    const label = cut(entry.label, 200);

    if (!label) return [];

    return [
      {
        label,
        points: Math.min(100, Math.max(0, Number(entry.points) || 0)),
        severity: SEVERITIES.has(entry.severity) ? entry.severity : "low",
        explanation: cut(entry.explanation, 1000),
      },
    ];
  });
}

export function sanitizeItem(raw, { previewLength = 120, makeId }) {
  if (!raw || typeof raw !== "object") return null;

  const type = TYPES.has(raw.type) ? raw.type : "URL";
  const score = Number(raw.score);
  const time = Date.parse(raw.scannedAt);

  if (!RISKS.has(raw.risk) || !Number.isFinite(score) || Number.isNaN(time)) {
    return null;
  }

  const url = type === "MESSAGE" ? "Message analysis" : cut(raw.url, 2048);

  if (!url) return null;

  const submittedContent =
    type === "MESSAGE"
      ? cut(raw.submittedContent, previewLength)
      : cut(raw.submittedContent, 2048);

  const safeId =
    typeof raw.id === "string" && /^[\w.-]{1,80}$/.test(raw.id)
      ? raw.id
      : makeId();

  return {
    id: safeId,
    type,
    url,
    risk: raw.risk,
    score: Math.min(100, Math.max(0, score)),
    scannedAt: new Date(time).toISOString(),
    indicators: cleanIndicators(raw.indicators),
    submittedContent,
    normalizedUrl: cut(raw.normalizedUrl, 2048),
    safetyNote: cut(raw.safetyNote, 1000),
  };
}

const duplicateKey = (item) =>
  `${item.type}|${
    item.type === "MESSAGE"
      ? item.submittedContent
      : item.normalizedUrl || item.url
  }|${item.scannedAt}`;

export function buildExport(history, now = new Date()) {
  const items = history
    .map((item) => sanitizeItem(item, { previewLength: 120, makeId: () => "x" }))
    .filter(Boolean);

  return {
    fileName: `phishcheck-history-${now.toISOString().slice(0, 10)}.json`,
    content: JSON.stringify(
      {
        format: EXPORT_FORMAT,
        version: EXPORT_VERSION,
        exportedAt: now.toISOString(),
        items,
      },
      null,
      2
    ),
  };
}

export function mergeImport(
  text,
  existing,
  {
    max = 20,
    previewLength = 120,
    random = Math.random,
    now = Date.now,
  } = {}
) {
  if (typeof text !== "string" || text.length === 0) {
    return { error: "The file is empty." };
  }

  if (text.length > MAX_FILE_CHARS) {
    return { error: "The file is too large to be a PhishCheck history file." };
  }

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    return { error: "This is not a valid PhishCheck history file." };
  }

  if (
    !data ||
    typeof data !== "object" ||
    data.format !== EXPORT_FORMAT ||
    !Array.isArray(data.items)
  ) {
    return { error: "This is not a valid PhishCheck history file." };
  }

  if (data.version > EXPORT_VERSION) {
    return {
      error:
        "This file was made by a newer version of PhishCheck. Update the app and try again.",
    };
  }

  const usedIds = new Set(existing.map((item) => item.id));
  const seen = new Set(existing.map(duplicateKey));

  const makeId = () => {
    let id;

    do {
      id = `${now()}-${random().toString(36).slice(2, 8)}`;
    } while (usedIds.has(id));

    return id;
  };

  const fresh = [];
  let invalid = 0;
  let duplicates = 0;

  for (const raw of data.items.slice(0, MAX_ITEMS_READ)) {
    const item = sanitizeItem(raw, { previewLength, makeId });

    if (!item) {
      invalid += 1;
      continue;
    }

    if (seen.has(duplicateKey(item))) {
      duplicates += 1;
      continue;
    }

    if (usedIds.has(item.id)) item.id = makeId();

    seen.add(duplicateKey(item));
    usedIds.add(item.id);
    fresh.push(item);
  }

  const items = [...existing, ...fresh]
    .sort((a, b) => Date.parse(b.scannedAt) - Date.parse(a.scannedAt))
    .slice(0, max);

  const kept = new Set(items.map((item) => item.id));
  const added = fresh.filter((item) => kept.has(item.id)).length;

  return {
    items,
    added,
    duplicates,
    invalid,
    trimmed: fresh.length - added,
  };
}

export function describeImport(outcome, max = 20) {
  const parts = [
    `Imported ${outcome.added} ${outcome.added === 1 ? "scan" : "scans"}.`,
  ];

  if (outcome.duplicates > 0) {
    parts.push(`${outcome.duplicates} already in your history.`);
  }

  if (outcome.invalid > 0) {
    parts.push(`${outcome.invalid} could not be read and were skipped.`);
  }

  if (outcome.trimmed > 0) {
    parts.push(
      `History keeps only the newest ${max}, so ${outcome.trimmed} older ${
        outcome.trimmed === 1 ? "scan was" : "scans were"
      } left out.`
    );
  }

  return parts.join(" ");
}
