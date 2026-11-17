import { randomUUID } from "node:crypto";

// Keeps everything in memory. Used for tests and local development only,
// because it is lost whenever the server restarts.
export function createMemoryStore() {
  const teams = new Map();
  const results = [];

  return {
    async createTeam({ name, joinCode, keyHash }) {
      if ([...teams.values()].some((team) => team.joinCode === joinCode)) {
        throw Object.assign(new Error("code taken"), { code: "CODE_TAKEN" });
      }

      const id = randomUUID();

      teams.set(id, { id, name, joinCode, keyHash });

      return { id };
    },

    async getTeamByCode(joinCode) {
      const team = [...teams.values()].find((item) => item.joinCode === joinCode);

      return team ? { id: team.id, name: team.name, keyHash: team.keyHash } : null;
    },

    async addResult({ teamId, score, total, language, missed }) {
      results.push({
        team_id: teamId,
        score,
        total,
        language,
        missed,
        created_at: new Date().toISOString(),
      });
    },

    async getResults(teamId) {
      return results.filter((row) => row.team_id === teamId).map((row) => ({ ...row }));
    },

    async deleteTeam(teamId) {
      teams.delete(teamId);

      for (let i = results.length - 1; i >= 0; i -= 1) {
        if (results[i].team_id === teamId) results.splice(i, 1);
      }
    },
  };
}
