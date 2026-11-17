import { API_BASE } from "./linkCheck.js";

const TIMEOUT_MS = 30000;

const NOT_SET_UP =
  "Team training needs the online service, which is not connected on this site yet.";
const UNREACHABLE =
  "The service could not be reached. It may be waking up, so wait a moment and try again.";

async function call(path, { method = "GET", body } = {}) {
  if (!API_BASE) return { ok: false, error: NOT_SET_UP };

  try {
    const response = await fetch(`${API_BASE}/api/teams${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: data.error || "Something went wrong. Please try again.",
      };
    }

    return { ok: true, data };
  } catch {
    return { ok: false, error: UNREACHABLE };
  }
}

export const teamServiceAvailable = Boolean(API_BASE);

export const createTeam = (name) => call("", { method: "POST", body: { name } });

export const getTeamInfo = (joinCode) =>
  call(`/${encodeURIComponent(joinCode)}/info`);

export const submitResult = (joinCode, result) =>
  call(`/${encodeURIComponent(joinCode)}/results`, { method: "POST", body: result });

export const getSummary = (joinCode, managerKey) =>
  call("/summary", { method: "POST", body: { joinCode, managerKey } });

export const deleteTeam = (joinCode, managerKey) =>
  call("/delete", { method: "POST", body: { joinCode, managerKey } });
