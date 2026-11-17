import express from "express";
import rateLimit from "express-rate-limit";
import {
  formatJoinCode,
  generateJoinCode,
  generateManagerKey,
  hashKey,
  keyMatches,
  normalizeJoinCode,
} from "./codes.js";
import { QUIZ_IDS, QUIZ_TOTAL } from "./ids.js";
import { summarizeResults } from "./summary.js";

const MAX_NAME_LENGTH = 60;
const MAX_RESULTS_PER_TEAM_PER_HOUR = 200;
const BAD_ACCESS = "The team code or manager key is not correct.";

function limiter(limit, windowMs) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { status: "error", error: "Too many requests. Please try again later." },
  });
}

const cleanName = (value) =>
  typeof value === "string"
    ? value.replace(/\p{Cc}/gu, "").trim()
    : "";

export function validateResult(body) {
  const { score, total, language, missed } = body || {};

  if (!Number.isInteger(total) || total !== QUIZ_TOTAL) return null;
  if (!Number.isInteger(score) || score < 0 || score > total) return null;
  if (language !== "en" && language !== "ar") return null;
  if (!Array.isArray(missed) || missed.length > total) return null;

  const unique = new Set(missed);

  if (unique.size !== missed.length) return null;
  if (missed.some((id) => !QUIZ_IDS.includes(id))) return null;

  // A round with N correct answers has exactly (total - N) misses.
  if (missed.length !== total - score) return null;

  return { score, total, language, missed: [...unique] };
}

export function createTeamRouter({
  store,
  now = Date.now,
  randomBytesFn,
  createLimit = 10,
  submitLimit = 120,
  readLimit = 60,
}) {
  const router = express.Router();
  const recent = new Map();

  // Stops one team from being flooded, even if its join code leaks.
  function teamIsBusy(teamId) {
    const hourAgo = now() - 60 * 60 * 1000;
    const times = (recent.get(teamId) || []).filter((time) => time > hourAgo);

    if (times.length >= MAX_RESULTS_PER_TEAM_PER_HOUR) {
      recent.set(teamId, times);
      return true;
    }

    times.push(now());
    recent.set(teamId, times);

    return false;
  }

  async function authorize(body) {
    const code = normalizeJoinCode(body?.joinCode);
    const key = typeof body?.managerKey === "string" ? body.managerKey : "";

    if (!code || !key) return null;

    const team = await store.getTeamByCode(code);

    return team && keyMatches(key, team.keyHash) ? team : null;
  }

  const guard = (handler) => async (req, res) => {
    try {
      await handler(req, res);
    } catch {
      // Neither codes, keys nor results are ever logged.
      console.error("TEAM TRAINING ERROR");
      res.status(503).json({
        status: "error",
        error: "Team training storage is not available right now. Please try again.",
      });
    }
  };

  router.post(
    "/",
    limiter(createLimit, 60 * 60 * 1000),
    guard(async (req, res) => {
      const rawName = req.body?.name;
      const name = cleanName(rawName);

      if (rawName !== undefined && typeof rawName !== "string") {
        return res.status(400).json({ status: "error", error: "The team name is not valid." });
      }

      if (name.length > MAX_NAME_LENGTH) {
        return res.status(400).json({
          status: "error",
          error: `The team name must be ${MAX_NAME_LENGTH} characters or fewer.`,
        });
      }

      const managerKey = generateManagerKey();
      const keyHash = hashKey(managerKey);

      for (let attempt = 0; attempt < 5; attempt += 1) {
        const joinCode = generateJoinCode(randomBytesFn);

        try {
          await store.createTeam({ name, joinCode, keyHash });

          return res.status(201).json({
            joinCode: formatJoinCode(joinCode),
            name,
            managerKey,
          });
        } catch (error) {
          if (error.code !== "CODE_TAKEN") throw error;
        }
      }

      throw new Error("could not create a unique code");
    })
  );

  router.get(
    "/:joinCode/info",
    limiter(readLimit, 15 * 60 * 1000),
    guard(async (req, res) => {
      const code = normalizeJoinCode(req.params.joinCode);
      const team = code ? await store.getTeamByCode(code) : null;

      if (!team) {
        return res.status(404).json({ status: "error", error: "That team code was not found." });
      }

      return res.json({ name: team.name });
    })
  );

  router.post(
    "/:joinCode/results",
    limiter(submitLimit, 15 * 60 * 1000),
    guard(async (req, res) => {
      const code = normalizeJoinCode(req.params.joinCode);
      const team = code ? await store.getTeamByCode(code) : null;

      if (!team) {
        return res.status(404).json({ status: "error", error: "That team code was not found." });
      }

      const result = validateResult(req.body);

      if (!result) {
        return res.status(400).json({ status: "error", error: "The quiz result is not valid." });
      }

      if (teamIsBusy(team.id)) {
        return res.status(429).json({
          status: "error",
          error: "This team has received too many results this hour. Please try later.",
        });
      }

      await store.addResult({ teamId: team.id, ...result });

      return res.status(201).json({ ok: true });
    })
  );

  router.post(
    "/summary",
    limiter(readLimit, 15 * 60 * 1000),
    guard(async (req, res) => {
      const team = await authorize(req.body);

      if (!team) return res.status(401).json({ status: "error", error: BAD_ACCESS });

      const rows = await store.getResults(team.id);

      return res.json({ name: team.name, ...summarizeResults(rows, now()) });
    })
  );

  router.post(
    "/delete",
    limiter(readLimit, 15 * 60 * 1000),
    guard(async (req, res) => {
      const team = await authorize(req.body);

      if (!team) return res.status(401).json({ status: "error", error: BAD_ACCESS });

      await store.deleteTeam(team.id);

      return res.json({ ok: true });
    })
  );

  return router;
}
