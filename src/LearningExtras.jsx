import { useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ClipboardCheck,
  ListChecks,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import {
  afterIncident,
  buildRound,
  quizQuestions,
  scoreMessage,
  verifySteps,
} from "./learningContent";

export function PhishingQuiz({ onTryIt }) {
  const [phase, setPhase] = useState("intro");
  const [round, setRound] = useState([]);
  const [index, setIndex] = useState(0);
  const [picked, setPicked] = useState(null);
  const [results, setResults] = useState([]);

  const startRound = () => {
    setRound(buildRound());
    setIndex(0);
    setPicked(null);
    setResults([]);
    setPhase("playing");
  };

  const question = round[index];
  const answered = picked !== null;
  const isCorrect = answered && picked === question.isScam;

  const choose = (saidScam) => {
    if (answered) return;

    setPicked(saidScam);
    setResults((current) => [
      ...current,
      { id: question.id, correct: saidScam === question.isScam },
    ]);
  };

  const next = () => {
    if (index + 1 >= round.length) {
      setPhase("done");
      return;
    }

    setIndex(index + 1);
    setPicked(null);
  };

  const correctCount = results.filter((item) => item.correct).length;

  return (
    <section className="panel learn-panel" aria-labelledby="quiz-title">
      <div className="panel-heading">
        <div className="panel-icon">
          <ListChecks size={21} />
        </div>

        <div>
          <h3 id="quiz-title">Can you spot the scam?</h3>
          <p>
            Read each message, then decide if it is a scam or genuine. Some
            are genuine on purpose, because trusting nothing is not safe either.
          </p>
        </div>
      </div>

      {phase === "intro" && (
        <div className="quiz-intro">
          <p>
            {`A round has 8 real-life style messages taken from ${quizQuestions.length} scenarios, including fake delivery fees, bank calls and job offers. All names and links are made up.`}
          </p>

          <button className="primary-button" type="button" onClick={startRound}>
            Start the quiz
            <ArrowRight size={17} />
          </button>
        </div>
      )}

      {phase === "playing" && question && (
        <div className="quiz-body">
          <div className="quiz-progress">
            <span>
              Question {index + 1} of {round.length}
            </span>

            <div
              className="quiz-bar"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={round.length}
              aria-valuenow={index + (answered ? 1 : 0)}
              aria-label="Quiz progress"
            >
              <span
                style={{
                  width: `${((index + (answered ? 1 : 0)) / round.length) * 100}%`,
                }}
              />
            </div>
          </div>

          <span className="quiz-channel">{question.channel}</span>

          {question.context && (
            <p className="quiz-context">
              <strong>Situation:</strong> {question.context}
            </p>
          )}

          <blockquote className="quiz-message">{question.content}</blockquote>

          <p className="quiz-ask">Is this a scam?</p>

          <div className="quiz-choices">
            <button
              type="button"
              className={`quiz-choice ${picked === true ? "chosen" : ""}`}
              onClick={() => choose(true)}
              disabled={answered}
              aria-pressed={picked === true}
            >
              <ShieldAlert size={17} />
              Scam
            </button>

            <button
              type="button"
              className={`quiz-choice ${picked === false ? "chosen" : ""}`}
              onClick={() => choose(false)}
              disabled={answered}
              aria-pressed={picked === false}
            >
              <ShieldCheck size={17} />
              Looks genuine
            </button>
          </div>

          <div aria-live="polite">
            {answered && (
              <div className={`quiz-feedback ${isCorrect ? "right" : "wrong"}`}>
                <h4>
                  {isCorrect ? (
                    <CheckCircle2 size={19} />
                  ) : (
                    <XCircle size={19} />
                  )}
                  {isCorrect ? "Correct" : "Not quite"}:{" "}
                  {question.isScam ? "this is a scam" : "this one is genuine"}
                </h4>

                <p>{question.explanation}</p>

                {question.redFlags.length > 0 && (
                  <>
                    <strong className="quiz-subtitle">Warning signs</strong>
                    <ul>
                      {question.redFlags.map((flag) => (
                        <li key={flag}>{flag}</li>
                      ))}
                    </ul>
                  </>
                )}

                <p className="quiz-action">
                  <strong>What to do:</strong> {question.action}
                </p>

                <div className="quiz-feedback-actions">
                  <button
                    className="primary-button"
                    type="button"
                    onClick={next}
                  >
                    {index + 1 >= round.length
                      ? "See my results"
                      : "Next question"}
                    <ArrowRight size={17} />
                  </button>

                  {question.kind !== "none" && (
                    <button
                      className="quiz-link-button"
                      type="button"
                      onClick={() => onTryIt?.(question)}
                    >
                      <Search size={15} />
                      Test this in PhishCheck
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {phase === "done" && (
        <div className="quiz-done">
          <div className="quiz-score">
            <strong>{correctCount}</strong>
            <span>of {round.length} correct</span>
          </div>

          <p>{scoreMessage(correctCount, round.length)}</p>

          {results.some((item) => !item.correct) && (
            <div className="quiz-review">
              <strong className="quiz-subtitle">Review the ones you missed</strong>
              <ul>
                {results
                  .filter((item) => !item.correct)
                  .map((item) => {
                    const missed = quizQuestions.find((q) => q.id === item.id);

                    return (
                      <li key={item.id}>
                        <span>{missed.channel}</span>
                        {missed.isScam ? " (scam): " : " (genuine): "}
                        {missed.explanation}
                      </li>
                    );
                  })}
              </ul>
            </div>
          )}

          <button className="primary-button" type="button" onClick={startRound}>
            <RotateCcw size={16} />
            Play again with new questions
          </button>
        </div>
      )}
    </section>
  );
}

export function VerifyChecklist() {
  const [done, setDone] = useState(() => new Set());

  const toggle = (id) => {
    setDone((current) => {
      const copy = new Set(current);

      if (copy.has(id)) copy.delete(id);
      else copy.add(id);

      return copy;
    });
  };

  return (
    <>
      <section className="panel learn-panel" aria-labelledby="verify-title">
        <div className="panel-heading">
          <div className="panel-icon">
            <ClipboardCheck size={21} />
          </div>

          <div>
            <h3 id="verify-title">How to verify a message safely</h3>
            <p>
              Go through these steps whenever a message, call or link asks you
              to do something. Your ticks are not saved anywhere.
            </p>
          </div>
        </div>

        <div className="verify-progress">
          <span>
            {done.size} of {verifySteps.length} steps done
          </span>

          <div
            className="quiz-bar"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={verifySteps.length}
            aria-valuenow={done.size}
            aria-label="Checklist progress"
          >
            <span style={{ width: `${(done.size / verifySteps.length) * 100}%` }} />
          </div>
        </div>

        <ol className="verify-list">
          {verifySteps.map((step, position) => (
            <li key={step.id} className={done.has(step.id) ? "ticked" : ""}>
              <label>
                <input
                  type="checkbox"
                  checked={done.has(step.id)}
                  onChange={() => toggle(step.id)}
                />

                <span className="verify-number">{position + 1}</span>

                <span className="verify-text">
                  <strong>{step.title}</strong>
                  <span>{step.detail}</span>
                </span>
              </label>
            </li>
          ))}
        </ol>

        {done.size > 0 && (
          <button
            className="quiz-link-button"
            type="button"
            onClick={() => setDone(new Set())}
          >
            <RotateCcw size={15} />
            Clear the ticks
          </button>
        )}
      </section>

      <section className="panel learn-panel" aria-labelledby="incident-title">
        <div className="panel-heading">
          <div className="panel-icon incident-icon">
            <ShieldAlert size={21} />
          </div>

          <div>
            <h3 id="incident-title">I already clicked or shared something</h3>
            <p>
              It happens to careful people. Choose what happened and follow the
              steps in order, starting with the first.
            </p>
          </div>
        </div>

        <div className="incident-list">
          {afterIncident.map((item) => (
            <details key={item.id} className="incident-item">
              <summary>
                {item.title}
                <ChevronDown size={17} />
              </summary>

              <ol>
                {item.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </details>
          ))}
        </div>
      </section>
    </>
  );
}
