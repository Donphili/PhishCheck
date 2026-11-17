import { useState } from "react";
import {
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";
import { quizQuestions } from "./learningContent";
import {
  createTeam,
  deleteTeam,
  getSummary,
  getTeamInfo,
  teamServiceAvailable,
} from "./teamApi";
import { buildStaffLink, normalizeJoinCode } from "./teamUtils";

const topicFor = (id) =>
  quizQuestions.find((question) => question.id === id)?.topic || id;

function CopyButton({ value, label }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <button className="neutral-button" type="button" onClick={copy}>
      <Copy size={16} />
      {copied ? "Copied" : label}
    </button>
  );
}

function Results({ summary, onDelete, deleting }) {
  const weeks = ["This week", "Last week", "2 weeks ago", "3 weeks ago"];
  const tallest = Math.max(1, ...summary.weekly);

  return (
    <div className="team-results">
      <h4>{summary.name || "Your team"}</h4>

      <div className="team-stats">
        <div>
          <strong>{summary.completions}</strong>
          <span>quizzes finished</span>
        </div>

        <div>
          <strong>{summary.completionsLast30Days}</strong>
          <span>in the last 30 days</span>
        </div>

        {summary.enoughData && (
          <>
            <div>
              <strong>{summary.averagePercent}%</strong>
              <span>average score</span>
            </div>

            <div>
              <strong>{summary.strongPercent}%</strong>
              <span>scored 75% or more</span>
            </div>
          </>
        )}
      </div>

      {!summary.enoughData && (
        <p className="team-note">
          Only {summary.completions} {summary.completions === 1 ? "quiz has" : "quizzes have"} been
          finished. Scores and the most missed topics appear after{" "}
          {summary.minForDetails} quizzes, so nobody's individual score can be
          worked out.
        </p>
      )}

      {summary.enoughData && (
        <>
          <strong className="quiz-subtitle">Most missed topics</strong>
          <ul className="team-missed">
            {summary.mostMissed.length === 0 && (
              <li>Nobody missed anything yet. Great start.</li>
            )}

            {summary.mostMissed.map((item) => (
              <li key={item.id}>
                <span>{topicFor(item.id)}</span>
                <em>
                  missed by {item.percent}% of quizzes ({item.count})
                </em>
              </li>
            ))}
          </ul>

          <p className="team-note">
            Language: {summary.languages.en} in English, {summary.languages.ar} in Arabic.
          </p>
        </>
      )}

      <strong className="quiz-subtitle">Quizzes finished per week</strong>

      <div className="team-weeks">
        {summary.weekly.map((count, index) => (
          <div key={weeks[index]}>
            <div className="team-week-bar">
              <span style={{ height: `${(count / tallest) * 100}%` }} />
            </div>
            <b>{count}</b>
            <small>{weeks[index]}</small>
          </div>
        ))}
      </div>

      <button
        className="secondary-button danger-button"
        type="button"
        onClick={onDelete}
        disabled={deleting}
      >
        <Trash2 size={16} />
        Delete this team and all its results
      </button>
    </div>
  );
}

export default function TeamTraining({ onJoin }) {
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [created, setCreated] = useState(null);

  const [code, setCode] = useState("");
  const [key, setKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [viewError, setViewError] = useState("");
  const [summary, setSummary] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const [joinCode, setJoinCode] = useState("");
  const [joinError, setJoinError] = useState("");
  const [joining, setJoining] = useState(false);

  const create = async (event) => {
    event.preventDefault();
    setCreateError("");
    setCreating(true);

    const outcome = await createTeam(name.trim());

    setCreating(false);

    if (!outcome.ok) {
      setCreateError(outcome.error);
      return;
    }

    setCreated(outcome.data);
    setName("");
  };

  const view = async (event) => {
    event.preventDefault();
    setViewError("");
    setSummary(null);

    if (!normalizeJoinCode(code) || !key.trim()) {
      setViewError("Enter the team code and the manager key.");
      return;
    }

    setLoading(true);

    const outcome = await getSummary(normalizeJoinCode(code), key.trim());

    setLoading(false);

    if (!outcome.ok) {
      setViewError(outcome.error);
      return;
    }

    setSummary(outcome.data);
  };

  const remove = async () => {
    const sure = window.confirm(
      "Delete this team and every result stored for it? This cannot be undone."
    );

    if (!sure) return;

    setDeleting(true);

    const outcome = await deleteTeam(normalizeJoinCode(code), key.trim());

    setDeleting(false);

    if (!outcome.ok) {
      setViewError(outcome.error);
      return;
    }

    setSummary(null);
    setKey("");
    setViewError("The team and its results have been deleted.");
  };

  const join = async (event) => {
    event.preventDefault();
    setJoinError("");

    const clean = normalizeJoinCode(joinCode);

    if (!clean) {
      setJoinError("That does not look like a team code. It has 8 letters and numbers.");
      return;
    }

    setJoining(true);

    const outcome = await getTeamInfo(clean);

    setJoining(false);

    if (!outcome.ok) {
      setJoinError(outcome.error);
      return;
    }

    onJoin({ code: clean, name: outcome.data.name });
  };

  return (
    <div className="team-page">
      <section className="panel learn-panel">
        <div className="panel-heading">
          <div className="panel-icon">
            <Users size={21} />
          </div>

          <div>
            <h3>Team training</h3>
            <p>
              Give your staff a short scam quiz in Arabic or English and see how
              the team is doing. You never see names or messages, only totals.
              Free during the trial.
            </p>
          </div>
        </div>

        {!teamServiceAvailable && (
          <p className="team-note">
            Team training needs the online service, which is not connected on
            this site yet.
          </p>
        )}

        <div className="team-privacy">
          <strong>What is stored</strong>
          <p>
            For each finished quiz: the score, the language, and which topics
            were missed. No names, no email addresses, no phone numbers and no
            message text. You can delete everything at any time.
          </p>
        </div>
      </section>

      <section className="panel learn-panel">
        <div className="panel-heading">
          <div className="panel-icon">
            <UserPlus size={21} />
          </div>

          <div>
            <h3>1. Create a team (managers)</h3>
            <p>
              You get a team code to share with staff and a manager key that
              only you should keep.
            </p>
          </div>
        </div>

        {!created && (
          <form onSubmit={create}>
            <label htmlFor="team-name">Business name (optional)</label>

            <div className="url-input-wrap">
              <input
                id="team-name"
                type="text"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="For example: Al Noor Trading"
                maxLength={60}
                autoComplete="off"
              />
            </div>

            {createError && <p className="form-error">{createError}</p>}

            <button
              className="primary-button"
              type="submit"
              disabled={creating || !teamServiceAvailable}
            >
              {creating ? "Creating..." : "Create my team"}
            </button>
          </form>
        )}

        {created && (
          <div className="team-created">
            <p className="team-success">
              <CheckCircle2 size={18} /> Your team is ready.
            </p>

            <div className="team-field">
              <span>Team code (share with staff)</span>
              <code>{created.joinCode}</code>
              <CopyButton value={created.joinCode} label="Copy code" />
            </div>

            <div className="team-field">
              <span>Staff link</span>
              <code>{buildStaffLink(window.location.origin, created.joinCode)}</code>
              <CopyButton
                value={buildStaffLink(window.location.origin, created.joinCode)}
                label="Copy link"
              />
            </div>

            <div className="team-field warning">
              <span>Manager key (keep private)</span>
              <code>{created.managerKey}</code>
              <CopyButton value={created.managerKey} label="Copy key" />
            </div>

            <p className="team-note strong">
              Save the manager key now, for example in your phone's notes or a
              password manager. It is shown only once and cannot be recovered.
              Anyone who has it can see your team's results.
            </p>

            <button
              className="neutral-button"
              type="button"
              onClick={() => {
                setCode(created.joinCode);
                setCreated(null);
              }}
            >
              I saved it
            </button>
          </div>
        )}
      </section>

      <section className="panel learn-panel">
        <div className="panel-heading">
          <div className="panel-icon">
            <Eye size={21} />
          </div>

          <div>
            <h3>2. See your team's results (managers)</h3>
            <p>Enter your team code and manager key.</p>
          </div>
        </div>

        <form onSubmit={view}>
          <label htmlFor="view-code">Team code</label>

          <div className="url-input-wrap">
            <input
              id="view-code"
              type="text"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="ABCD-EFGH"
              autoComplete="off"
              maxLength={20}
            />
          </div>

          <label htmlFor="view-key">Manager key</label>

          <div className="url-input-wrap">
            <input
              id="view-key"
              type={showKey ? "text" : "password"}
              value={key}
              onChange={(event) => setKey(event.target.value)}
              placeholder="mk_..."
              autoComplete="off"
              maxLength={100}
            />

            <button
              type="button"
              className="icon-toggle"
              onClick={() => setShowKey((current) => !current)}
              aria-label={showKey ? "Hide the key" : "Show the key"}
            >
              {showKey ? <EyeOff size={17} /> : <Eye size={17} />}
            </button>
          </div>

          {viewError && <p className="form-error">{viewError}</p>}

          <button
            className="primary-button"
            type="submit"
            disabled={loading || !teamServiceAvailable}
          >
            {loading ? "Loading..." : "Show results"}
          </button>
        </form>

        {summary && (
          <Results summary={summary} onDelete={remove} deleting={deleting} />
        )}
      </section>

      <section className="panel learn-panel">
        <div className="panel-heading">
          <div className="panel-icon">
            <Users size={21} />
          </div>

          <div>
            <h3>Join your team (staff)</h3>
            <p>
              Enter the code your manager gave you, then take the quiz. After
              each round you choose whether to send your score. Your name is
              never sent.
            </p>
          </div>
        </div>

        <form onSubmit={join}>
          <label htmlFor="join-code">Team code</label>

          <div className="url-input-wrap">
            <input
              id="join-code"
              type="text"
              value={joinCode}
              onChange={(event) => setJoinCode(event.target.value)}
              placeholder="ABCD-EFGH"
              autoComplete="off"
              maxLength={20}
            />
          </div>

          {joinError && <p className="form-error">{joinError}</p>}

          <button
            className="primary-button"
            type="submit"
            disabled={joining || !teamServiceAvailable}
          >
            {joining ? "Checking..." : "Join and start training"}
          </button>
        </form>
      </section>
    </div>
  );
}

