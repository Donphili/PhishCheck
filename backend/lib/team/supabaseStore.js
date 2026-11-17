// Stores team data in Supabase through its REST interface. The server uses a
// secret key, so the database needs no public access (see sql/team_training.sql).

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CODE = /^[A-Z0-9]{8}$/;

export function createSupabaseStore({ url, key, fetchImpl = fetch, timeoutMs = 10000 }) {
  const base = `${url.replace(/\/+$/, "")}/rest/v1`;

  async function request(path, { method = "GET", body, prefer } = {}) {
    const headers = {
      apikey: key,
      "Content-Type": "application/json",
    };

    // Older keys are JWTs and are also sent as a bearer token. Newer
    // "secret" keys are not JWTs and go in the apikey header only.
    if (key.startsWith("eyJ")) headers.Authorization = `Bearer ${key}`;
    if (prefer) headers.Prefer = prefer;

    return fetchImpl(`${base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  }

  const fail = (response) => new Error(`Storage error ${response.status}`);

  return {
    async createTeam({ name, joinCode, keyHash }) {
      const response = await request("/teams", {
        method: "POST",
        prefer: "return=representation",
        body: { join_code: joinCode, name, manager_key_hash: keyHash },
      });

      if (response.status === 409) {
        throw Object.assign(new Error("code taken"), { code: "CODE_TAKEN" });
      }

      if (!response.ok) throw fail(response);

      const rows = await response.json();

      return { id: rows[0].id };
    },

    async getTeamByCode(joinCode) {
      if (!CODE.test(joinCode)) return null;

      const response = await request(
        `/teams?join_code=eq.${joinCode}&select=id,name,manager_key_hash&limit=1`
      );

      if (!response.ok) throw fail(response);

      const [team] = await response.json();

      return team
        ? { id: team.id, name: team.name, keyHash: team.manager_key_hash }
        : null;
    },

    async addResult({ teamId, score, total, language, missed }) {
      const response = await request("/quiz_results", {
        method: "POST",
        prefer: "return=minimal",
        body: { team_id: teamId, score, total, language, missed },
      });

      if (!response.ok) throw fail(response);
    },

    async getResults(teamId) {
      if (!UUID.test(teamId)) return [];

      const response = await request(
        `/quiz_results?team_id=eq.${teamId}&select=score,total,language,missed,created_at&order=created_at.desc&limit=5000`
      );

      if (!response.ok) throw fail(response);

      return response.json();
    },

    async deleteTeam(teamId) {
      if (!UUID.test(teamId)) return;

      const response = await request(`/teams?id=eq.${teamId}`, { method: "DELETE" });

      if (!response.ok) throw fail(response);
    },
  };
}
