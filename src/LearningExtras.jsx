import { useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ClipboardCheck,
  Languages,
  ListChecks,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import {
  buildRound,
  getAfterIncident,
  getVerifySteps,
  localizeQuestion,
  quizQuestions,
  scoreMessage,
} from "./learningContent";

const LANG_KEY = "phishcheck-learning-language";

const UI = {
  en: {
    switchLabel: "Switch to Arabic",
    switchText: "العربية",
    quizTitle: "Can you spot the scam?",
    quizSubtitle:
      "Read each message, then decide if it is a scam or genuine. Some are genuine on purpose, because trusting nothing is not safe either.",
    quizIntro: (count) =>
      `A round has 8 real-life style messages taken from ${count} scenarios, including fake delivery fees, bank calls and job offers. All names and links are made up.`,
    start: "Start the quiz",
    questionOf: (index, total) => `Question ${index} of ${total}`,
    progress: "Quiz progress",
    situation: "Situation:",
    ask: "Is this a scam?",
    scam: "Scam",
    genuine: "Looks genuine",
    correct: "Correct",
    notQuite: "Not quite",
    isScam: "this is a scam",
    isGenuine: "this one is genuine",
    warningSigns: "Warning signs",
    whatToDo: "What to do:",
    next: "Next question",
    results: "See my results",
    testIt: "Test this in PhishCheck",
    correctOf: (total) => `of ${total} correct`,
    review: "Review the ones you missed",
    scamTag: " (scam): ",
    genuineTag: " (genuine): ",
    playAgain: "Play again with new questions",
    verifyTitle: "How to verify a message safely",
    verifySubtitle:
      "Go through these steps whenever a message, call or link asks you to do something. Your ticks are not saved anywhere.",
    stepsDone: (done, total) => `${done} of ${total} steps done`,
    checklistProgress: "Checklist progress",
    clearTicks: "Clear the ticks",
    incidentTitle: "I already clicked or shared something",
    incidentSubtitle:
      "It happens to careful people. Choose what happened and follow the steps in order, starting with the first.",
  },
  ar: {
    switchLabel: "التبديل إلى الإنجليزية",
    switchText: "English",
    quizTitle: "هل تستطيع اكتشاف الاحتيال؟",
    quizSubtitle:
      "اقرأ كل رسالة ثم قرر هل هي احتيال أم رسالة سليمة. بعضها سليم عمداً، لأن عدم الثقة بأي شيء ليس آمناً أيضاً.",
    quizIntro: (count) =>
      `تتكون الجولة من 8 رسائل تشبه ما يصل إلى الناس فعلاً، مختارة من ${count} سيناريو، منها رسوم توصيل مزيفة ومكالمات بنكية وعروض عمل. جميع الأسماء والروابط مختلقة.`,
    start: "ابدأ الاختبار",
    questionOf: (index, total) => `السؤال ${index} من ${total}`,
    progress: "تقدم الاختبار",
    situation: "الموقف:",
    ask: "هل هذه رسالة احتيال؟",
    scam: "احتيال",
    genuine: "تبدو سليمة",
    correct: "صحيح",
    notQuite: "ليس تماماً",
    isScam: "هذه رسالة احتيال",
    isGenuine: "هذه رسالة سليمة",
    warningSigns: "علامات تحذيرية",
    whatToDo: "ماذا تفعل:",
    next: "السؤال التالي",
    results: "عرض نتيجتي",
    testIt: "جرّب هذه الرسالة في PhishCheck",
    correctOf: (total) => `صحيحة من ${total}`,
    review: "راجع الأسئلة التي أخطأت فيها",
    scamTag: " (احتيال): ",
    genuineTag: " (سليمة): ",
    playAgain: "العب مجدداً بأسئلة جديدة",
    verifyTitle: "كيف تتحقق من رسالة بأمان",
    verifySubtitle:
      "اتبع هذه الخطوات كلما طلبت منك رسالة أو مكالمة أو رابط فعل شيء. علامات الإنجاز لا تُحفظ في أي مكان.",
    stepsDone: (done, total) => `تمت ${done} من ${total} خطوات`,
    checklistProgress: "تقدم قائمة التحقق",
    clearTicks: "مسح العلامات",
    incidentTitle: "لقد ضغطت على رابط أو شاركت شيئاً بالفعل",
    incidentSubtitle:
      "يحدث ذلك حتى للحذرين. اختر ما حدث معك واتبع الخطوات بالترتيب بدءاً من الأولى.",
  },
};

function readLanguage() {
  try {
    return localStorage.getItem(LANG_KEY) === "ar" ? "ar" : "en";
  } catch {
    return "en";
  }
}

export function PhishingQuiz({ onTryIt, lang = "en" }) {
  const text = UI[lang];
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

  // The round keeps the question order; the text follows the chosen language.
  const base = round[index];
  const question = base ? localizeQuestion(base, lang) : null;
  const answered = picked !== null;
  const isCorrect = answered && picked === base.isScam;

  const choose = (saidScam) => {
    if (answered) return;

    setPicked(saidScam);
    setResults((current) => [
      ...current,
      { id: base.id, correct: saidScam === base.isScam },
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
          <h3 id="quiz-title">{text.quizTitle}</h3>
          <p>{text.quizSubtitle}</p>
        </div>
      </div>

      {phase === "intro" && (
        <div className="quiz-intro">
          <p>{text.quizIntro(quizQuestions.length)}</p>

          <button className="primary-button" type="button" onClick={startRound}>
            {text.start}
            <ArrowRight size={17} className="rtl-flip" />
          </button>
        </div>
      )}

      {phase === "playing" && question && (
        <div className="quiz-body">
          <div className="quiz-progress">
            <span>{text.questionOf(index + 1, round.length)}</span>

            <div
              className="quiz-bar"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={round.length}
              aria-valuenow={index + (answered ? 1 : 0)}
              aria-label={text.progress}
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
              <strong>{text.situation}</strong> {question.context}
            </p>
          )}

          <blockquote
            className="quiz-message"
            dir={question.kind === "link" ? "ltr" : undefined}
          >
            {question.content}
          </blockquote>

          <p className="quiz-ask">{text.ask}</p>

          <div className="quiz-choices">
            <button
              type="button"
              className={`quiz-choice ${picked === true ? "chosen" : ""}`}
              onClick={() => choose(true)}
              disabled={answered}
              aria-pressed={picked === true}
            >
              <ShieldAlert size={17} />
              {text.scam}
            </button>

            <button
              type="button"
              className={`quiz-choice ${picked === false ? "chosen" : ""}`}
              onClick={() => choose(false)}
              disabled={answered}
              aria-pressed={picked === false}
            >
              <ShieldCheck size={17} />
              {text.genuine}
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
                  {isCorrect ? text.correct : text.notQuite}:{" "}
                  {base.isScam ? text.isScam : text.isGenuine}
                </h4>

                <p>{question.explanation}</p>

                {question.redFlags.length > 0 && (
                  <>
                    <strong className="quiz-subtitle">{text.warningSigns}</strong>
                    <ul>
                      {question.redFlags.map((flag) => (
                        <li key={flag}>{flag}</li>
                      ))}
                    </ul>
                  </>
                )}

                <p className="quiz-action">
                  <strong>{text.whatToDo}</strong> {question.action}
                </p>

                <div className="quiz-feedback-actions">
                  <button
                    className="primary-button"
                    type="button"
                    onClick={next}
                  >
                    {index + 1 >= round.length ? text.results : text.next}
                    <ArrowRight size={17} className="rtl-flip" />
                  </button>

                  {question.kind !== "none" && (
                    <button
                      className="quiz-link-button"
                      type="button"
                      onClick={() => onTryIt?.(question)}
                    >
                      <Search size={15} />
                      {text.testIt}
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
            <span>{text.correctOf(round.length)}</span>
          </div>

          <p>{scoreMessage(correctCount, round.length, lang)}</p>

          {results.some((item) => !item.correct) && (
            <div className="quiz-review">
              <strong className="quiz-subtitle">{text.review}</strong>
              <ul>
                {results
                  .filter((item) => !item.correct)
                  .map((item) => {
                    const missed = localizeQuestion(
                      quizQuestions.find((q) => q.id === item.id),
                      lang
                    );

                    return (
                      <li key={item.id}>
                        <span>{missed.channel}</span>
                        {missed.isScam ? text.scamTag : text.genuineTag}
                        {missed.explanation}
                      </li>
                    );
                  })}
              </ul>
            </div>
          )}

          <button className="primary-button" type="button" onClick={startRound}>
            <RotateCcw size={16} />
            {text.playAgain}
          </button>
        </div>
      )}
    </section>
  );
}

export function VerifyChecklist({ lang = "en" }) {
  const text = UI[lang];
  const steps = getVerifySteps(lang);
  const incidents = getAfterIncident(lang);
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
            <h3 id="verify-title">{text.verifyTitle}</h3>
            <p>{text.verifySubtitle}</p>
          </div>
        </div>

        <div className="verify-progress">
          <span>{text.stepsDone(done.size, steps.length)}</span>

          <div
            className="quiz-bar"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={steps.length}
            aria-valuenow={done.size}
            aria-label={text.checklistProgress}
          >
            <span style={{ width: `${(done.size / steps.length) * 100}%` }} />
          </div>
        </div>

        <ol className="verify-list">
          {steps.map((step, position) => (
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
            {text.clearTicks}
          </button>
        )}
      </section>

      <section className="panel learn-panel" aria-labelledby="incident-title">
        <div className="panel-heading">
          <div className="panel-icon incident-icon">
            <ShieldAlert size={21} />
          </div>

          <div>
            <h3 id="incident-title">{text.incidentTitle}</h3>
            <p>{text.incidentSubtitle}</p>
          </div>
        </div>

        <div className="incident-list">
          {incidents.map((item) => (
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

// The quiz and checklist with an English / Arabic switch. Arabic flips the
// layout to right-to-left.
export function LearningExtras({ onTryIt }) {
  const [lang, setLang] = useState(readLanguage);
  const text = UI[lang];

  const switchLanguage = () => {
    const nextLang = lang === "ar" ? "en" : "ar";

    setLang(nextLang);

    try {
      localStorage.setItem(LANG_KEY, nextLang);
    } catch {
      // A saved language is only a convenience, so ignore storage problems.
    }
  };

  return (
    <div
      className="learn-extras"
      dir={lang === "ar" ? "rtl" : "ltr"}
      lang={lang}
    >
      <div className="lang-switch">
        <button
          type="button"
          className="neutral-button"
          onClick={switchLanguage}
          aria-label={text.switchLabel}
          lang={lang === "ar" ? "en" : "ar"}
        >
          <Languages size={17} />
          {text.switchText}
        </button>
      </div>

      <PhishingQuiz lang={lang} onTryIt={onTryIt} />
      <VerifyChecklist lang={lang} />
    </div>
  );
}
