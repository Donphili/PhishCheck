import { createHash } from "node:crypto";
import { domainToASCII } from "node:url";

// Implements the URL canonicalization and hash-expression rules that Google
// Safe Browsing requires. All work is done on "byte strings" (one character
// per byte) so that results match the specification exactly.

function unescapeFully(value) {
  let current = value;

  for (let round = 0; round < 20; round += 1) {
    const next = current.replace(/%([0-9a-fA-F]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );

    if (next === current) break;
    current = next;
  }

  return current;
}

function normalizeIPv4(host) {
  const parts = host.split(".");

  if (parts.length < 1 || parts.length > 4) return null;

  const numbers = [];

  for (const part of parts) {
    let value;

    if (/^0x[0-9a-f]+$/i.test(part)) value = parseInt(part, 16);
    else if (/^0[0-7]*$/.test(part)) value = parseInt(part || "0", 8);
    else if (/^[1-9]\d*$/.test(part)) value = parseInt(part, 10);
    else return null;

    if (Number.isNaN(value)) return null;

    numbers.push(value);
  }

  const last = numbers[numbers.length - 1];

  if (last >= 256 ** (5 - numbers.length)) return null;

  for (let i = 0; i < numbers.length - 1; i += 1) {
    if (numbers[i] > 255) return null;
  }

  let total = last;

  for (let i = 0; i < numbers.length - 1; i += 1) {
    total += numbers[i] * 256 ** (3 - i);
  }

  return [24, 16, 8, 0]
    .map((shift) => Math.floor(total / 2 ** shift) % 256)
    .join(".");
}

function resolvePath(path) {
  const segments = path.split("/");
  const output = [];

  for (let i = 1; i < segments.length; i += 1) {
    const segment = segments[i];
    const isLast = i === segments.length - 1;

    if (segment === ".") {
      if (isLast) output.push("");
      continue;
    }

    if (segment === "..") {
      output.pop();
      if (isLast) output.push("");
      continue;
    }

    if (segment === "" && !isLast) continue;

    output.push(segment);
  }

  return `/${output.join("/")}`;
}

function escapeBytes(value) {
  let result = "";

  for (const character of value) {
    const code = character.charCodeAt(0);

    if (code <= 0x20 || code >= 0x7f || code === 0x23 || code === 0x25) {
      result += `%${code.toString(16).toUpperCase().padStart(2, "0")}`;
    } else {
      result += character;
    }
  }

  return result;
}

export function canonicalizeUrl(input) {
  let value = Buffer.from(String(input).trim(), "utf8").toString("latin1");

  value = value.replace(/[\t\r\n]/g, "");

  const fragmentIndex = value.indexOf("#");
  if (fragmentIndex >= 0) value = value.slice(0, fragmentIndex);

  value = unescapeFully(value);
  value = value.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");

  const boundary = value.search(/[/?]/);
  let hostPart = boundary < 0 ? value : value.slice(0, boundary);
  let rest = boundary < 0 ? "/" : value.slice(boundary);

  if (rest.startsWith("?")) rest = `/${rest}`;

  const atIndex = hostPart.lastIndexOf("@");
  if (atIndex >= 0) hostPart = hostPart.slice(atIndex + 1);

  hostPart = hostPart.replace(/:\d*$/, "");

  let host = hostPart
    .replace(/^\.+|\.+$/g, "")
    .replace(/\.{2,}/g, ".")
    .toLowerCase();

  if (/[\x80-\xff]/.test(host)) {
    const ascii = domainToASCII(Buffer.from(host, "latin1").toString("utf8"));
    if (ascii) host = ascii;
  }

  host = normalizeIPv4(host) || host;

  const queryIndex = rest.indexOf("?");
  const rawPath = queryIndex < 0 ? rest : rest.slice(0, queryIndex);
  const query = queryIndex < 0 ? "" : rest.slice(queryIndex);

  const path = resolvePath(rawPath);

  return {
    host: escapeBytes(host),
    path: escapeBytes(path),
    query: escapeBytes(query),
    hasQuery: queryIndex >= 0,
    url: `http://${escapeBytes(host)}${escapeBytes(path)}${escapeBytes(query)}`,
  };
}

function isIPv4(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

export function urlExpressions(input) {
  const { host, path, query, hasQuery } = canonicalizeUrl(input);

  const hosts = [host];

  if (!isIPv4(host)) {
    const components = host.split(".");
    const start = Math.min(5, components.length - 1);

    for (let count = start; count >= 2; count -= 1) {
      hosts.push(components.slice(-count).join("."));
    }
  }

  const paths = [];

  if (hasQuery) paths.push(`${path}${query}`);
  paths.push(path);

  const directories = path.split("/").slice(1, -1);
  let prefix = "/";

  paths.push(prefix);

  for (const directory of directories.slice(0, 3)) {
    prefix += `${directory}/`;
    paths.push(prefix);
  }

  const expressions = [];

  for (const hostName of new Set(hosts)) {
    for (const pathName of new Set(paths)) {
      expressions.push(`${hostName}${pathName}`);
    }
  }

  return [...new Set(expressions)];
}

export function sha256Latin1(value) {
  return createHash("sha256").update(value, "latin1").digest();
}
