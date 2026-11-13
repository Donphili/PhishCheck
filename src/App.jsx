
import { useEffect, useMemo, useState } from "react";
import { jsPDF } from "jspdf";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Download,
  ExternalLink,
  FileSearch,
  History,
  Home,
  Info,
  Link2,
  Menu,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { analyzeUrl, analyzeMessage } from "./securityEngine";
import { applyLinkCheck, checkLink, linkCheckEnabled } from "./linkCheck";
import { PhishingQuiz, VerifyChecklist } from "./LearningExtras";
import "./App.css";

const HISTORY_KEY = "phishcheck-url-history";
const MAX_HISTORY = 20;
const MAX_URL_LENGTH = 2048;
// Pasted messages can contain private details, so history keeps only a preview.
const HISTORY_MESSAGE_PREVIEW = 120;
const MAX_MESSAGE_LENGTH = 10000;

function readHistory() {
  try {
    const savedHistory = localStorage.getItem(HISTORY_KEY);
    if (!savedHistory) return [];

    const parsedHistory = JSON.parse(savedHistory);
    if (!Array.isArray(parsedHistory)) return [];

    return parsedHistory
      .filter(
        (item) =>
          item &&
          typeof item.id === "string" &&
          typeof item.url === "string" &&
          typeof item.risk === "string" &&
          typeof item.score === "number" &&
          typeof item.scannedAt === "string"
      )
      .slice(0, MAX_HISTORY);
  } catch {
    return [];
  }
}

function normalizeAnalysis(analysis, type) {
  if (!analysis || analysis.error) return analysis;

  const timestamp =
    analysis.scannedAt ||
    analysis.analyzedAt ||
    new Date().toISOString();

  const risk = analysis.risk || analysis.riskLevel || "Low";

  return {
    ...analysis,
    type,
    risk,
    riskLevel: risk,
    url:
      type === "MESSAGE"
        ? "Message analysis"
        : analysis.url || analysis.input || "",
    submittedContent: analysis.submittedContent || analysis.input || "",
    scannedAt: timestamp,
    score: Math.min(100, Math.max(0, Number(analysis.score) || 0)),
    indicators: Array.isArray(analysis.indicators)
      ? analysis.indicators
      : [],
  };
}

function getRiskGuidance(result) {
  const isMessage = result.type === "MESSAGE";

  if (result.risk === "High") {
    return {
      heading: "Take extra care before proceeding",
      summary: isMessage
        ? "This message contains several warning signs commonly found in social-engineering attempts."
        : "This address contains several patterns commonly associated with suspicious or misleading links.",
      actions: [
        "Do not enter passwords, payment details, or verification codes.",
        "Do not download attachments or follow instructions from this content.",
        "Contact the organization through its official website or app if the message claims to come from it.",
        "Report the message or link through the appropriate platform if you believe it is fraudulent.",
      ],
    };
  }

  if (result.risk === "Moderate") {
    return {
      heading: "Check the details before taking action",
      summary: isMessage
        ? "The message contains warning signs that deserve further checking."
        : "The address contains some patterns that deserve closer inspection.",
      actions: [
        "Check the sender and actual website domain carefully.",
        "Avoid signing in or sharing personal information through an unexpected link.",
        "Open the organization's official website or app yourself to check the request.",
        "Be cautious with unexpected attachments, payment requests, and urgent instructions.",
      ],
    };
  }

  return {
    heading: "Continue to use normal caution",
    summary: isMessage
      ? "This check found few common warning patterns in the message."
      : "This check found few common warning patterns in the address.",
    actions: [
      "Check that the sender and website address are the ones you intended to use.",
      "Be careful with unexpected requests for passwords, payment, or verification codes.",
      "Use a trusted route to visit important accounts and services.",
      "Keep your browser, device, and account security settings up to date.",
    ],
  };
}

function getIndicatorCount(item) {
  if (Array.isArray(item.indicators)) return item.indicators.length;
  if (typeof item.indicators === "number") return item.indicators;
  return 0;
}

function getHistorySearchText(item) {
  return [
    item.url,
    item.submittedContent,
    item.type,
    item.risk,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function exportRiskReport(result) {
  if (!result) return;

  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 18;
  const contentWidth = pageWidth - margin * 2;
  let y = 20;

  const guidance = getRiskGuidance(result);
  const safeScore = Math.min(100, Math.max(0, Number(result.score) || 0));

  const addPageIfNeeded = (requiredHeight = 12) => {
    if (y + requiredHeight > pageHeight - 18) {
      doc.addPage();
      y = 20;
    }
  };

  const addSectionTitle = (title) => {
    addPageIfNeeded(18);
    y += 5;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(20, 45, 65);
    doc.text(title, margin, y);
    y += 8;
  };

  const addParagraph = (text, options = {}) => {
    const fontSize = options.fontSize || 9;
    const lineHeight = options.lineHeight || 4.8;
    const color = options.color || [65, 75, 85];

    doc.setFont("helvetica", options.bold ? "bold" : "normal");
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);

    const lines = doc.splitTextToSize(
      String(text || ""),
      contentWidth
    );

    lines.forEach((line) => {
      addPageIfNeeded(lineHeight + 2);
      doc.text(line, margin, y);
      y += lineHeight;
    });

    y += 2;
  };

  const addBullet = (text) => {
    const lines = doc.splitTextToSize(
      String(text || ""),
      contentWidth - 5
    );

    lines.forEach((line, index) => {
      addPageIfNeeded(7);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(65, 75, 85);
      doc.text(index === 0 ? "•" : "", margin + 1, y);
      doc.text(line, margin + 5, y);
      y += 4.8;
    });

    y += 1.5;
  };

  const scannedDate = new Date(result.scannedAt);
  const formattedDate = Number.isNaN(scannedDate.getTime())
    ? "Date unavailable"
    : scannedDate.toLocaleString();

  const isMessage = result.type === "MESSAGE";

  const submittedContent = isMessage
    ? result.submittedContent || "Message content unavailable"
    : result.url || "URL unavailable";

  doc.setFillColor(10, 25, 43);
  doc.rect(0, 0, pageWidth, 43, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.text("PhishCheck", margin, 19);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text("SECURITY AWARENESS REPORT", margin, 27);

  doc.setFontSize(8);
  doc.text("Built for safer digital habits", margin, 34);

  y = 55;

  doc.setTextColor(20, 45, 65);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text("Scan Report", margin, y);
  y += 9;

  addParagraph(`Report type: ${result.type}`, { bold: true });
  addParagraph(`Date scanned: ${formattedDate}`);
  addParagraph(`Risk level: ${result.risk}`, { bold: true });
  addParagraph(`Risk score: ${safeScore}/100`, { bold: true });

  addPageIfNeeded(15);

  doc.setFillColor(225, 231, 237);
  doc.roundedRect(margin, y, contentWidth, 5, 2, 2, "F");

  const scoreWidth = (contentWidth * safeScore) / 100;

  if (result.risk === "High") {
    doc.setFillColor(220, 65, 65);
  } else if (result.risk === "Moderate") {
    doc.setFillColor(225, 160, 45);
  } else {
    doc.setFillColor(40, 165, 110);
  }

  if (scoreWidth > 0) {
    doc.roundedRect(margin, y, scoreWidth, 5, 2, 2, "F");
  }

  y += 13;

  addSectionTitle("Assessment summary");
  addParagraph(guidance.heading, { bold: true });
  addParagraph(guidance.summary);

  addSectionTitle(isMessage ? "Analyzed message" : "Analyzed URL");

  addParagraph(submittedContent, {
    fontSize: 8,
    lineHeight: 4.2,
  });

  if (
    !isMessage &&
    result.normalizedUrl &&
    result.normalizedUrl !== result.url
  ) {
    addParagraph(`Normalized address: ${result.normalizedUrl}`, {
      fontSize: 8,
      lineHeight: 4.2,
    });
  }

  addSectionTitle("Detected indicators");

  if (!result.indicators || result.indicators.length === 0) {
    addParagraph(
      "No common warning patterns were detected by this basic check."
    );
  } else {
    result.indicators.forEach((indicator, index) => {
      addPageIfNeeded(28);

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(20, 45, 65);

      doc.text(
        `${index + 1}. ${indicator.label} (+${indicator.points})`,
        margin,
        y
      );

      y += 5;

      addParagraph(indicator.explanation, {
        fontSize: 8,
        lineHeight: 4.2,
      });

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);
      doc.setTextColor(110, 120, 130);

      doc.text(
        `Severity: ${String(
          indicator.severity || "information"
        ).toUpperCase()}`,
        margin,
        y
      );

      y += 5;
    });
  }

  addSectionTitle("Recommended next steps");
  guidance.actions.forEach(addBullet);

  addSectionTitle("Important safety note");

  addParagraph(
    result.safetyNote ||
      "PhishCheck uses educational heuristic checks. It does not connect to live threat-intelligence services or confirm whether a website or message is malicious. A high score does not prove malicious activity, and a low score does not guarantee safety. Verify unexpected requests through official channels.",
    {
      fontSize: 8,
      lineHeight: 4.2,
    }
  );

  const pageCount = doc.internal.getNumberOfPages();

  for (let page = 1; page <= pageCount; page += 1) {
    doc.setPage(page);

    doc.setDrawColor(220, 225, 230);
    doc.line(
      margin,
      pageHeight - 13,
      pageWidth - margin,
      pageHeight - 13
    );

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(120, 130, 140);

    doc.text(
      "PhishCheck | Security Awareness",
      margin,
      pageHeight - 8
    );

    doc.text(
      `Page ${page} of ${pageCount}`,
      pageWidth - margin,
      pageHeight - 8,
      { align: "right" }
    );
  }

  const fileDate = Number.isNaN(scannedDate.getTime())
    ? new Date().toISOString().slice(0, 10)
    : scannedDate.toISOString().slice(0, 10);

  doc.save(
    `PhishCheck-${result.type}-Report-${fileDate}.pdf`
  );
}

function RiskReport({ result }) {
  if (!result) return null;

  const riskClass = result.risk.toLowerCase();
  const isMessage = result.type === "MESSAGE";
  const guidance = getRiskGuidance(result);

  const riskCaption =
    result.risk === "High"
      ? "Several warning signs were detected. Avoid interacting with this content until you have checked it independently."
      : result.risk === "Moderate"
        ? "Some warning signs were detected. Review the details before following instructions or sharing information."
        : "Few common warning signs were detected. This result cannot guarantee that the content is safe.";

  return (
    <section className="result-card">
      <div className="result-topline">
        <span className="eyebrow">
          <Activity size={15} />
          ANALYSIS COMPLETE · {result.type}
        </span>

        <span className="scan-time">
          {new Date(result.scannedAt).toLocaleString()}
        </span>
      </div>

      <div className="result-heading">
        <div>
          <h2>Risk assessment</h2>
          <p className="result-description">
            Review the findings and recommended actions from this local analysis.
          </p>
        </div>

        <span className={`risk-badge ${riskClass}`}>
          {result.risk === "High" && <ShieldAlert size={15} />}
          {result.risk === "Moderate" && <AlertTriangle size={15} />}
          {result.risk === "Low" && <ShieldCheck size={15} />}
          {result.risk} risk
        </span>
      </div>

      <div className="score-section">
        <div className="score-line">
          <span>Risk score</span>
          <strong>{result.score}/100</strong>
        </div>

        <div
          className="score-track"
          role="progressbar"
          aria-label="Risk score"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={result.score}
        >
          <div
            className={`score-fill ${riskClass}`}
            style={{ width: `${result.score}%` }}
          />
        </div>

        <p className="score-caption">{riskCaption}</p>
      </div>

      <div className="scanned-address">
        <span>
          {isMessage ? "Analyzed message" : "Analyzed address"}
        </span>

        <p>
          {isMessage ? result.submittedContent : result.url}
        </p>
      </div>

      <section className="indicators-section">
        <h3>Assessment summary</h3>

        <div className="safety-note">
          {result.risk === "High" ? (
            <ShieldAlert size={19} />
          ) : result.risk === "Moderate" ? (
            <AlertTriangle size={19} />
          ) : (
            <ShieldCheck size={19} />
          )}

          <div>
            <strong>{guidance.heading}</strong>
            <p>{guidance.summary}</p>
          </div>
        </div>
      </section>

      <div className="indicators-section">
        <h3>Detected indicators ({result.indicators.length})</h3>

        {result.indicators.length === 0 ? (
          <div className="empty-indicators">
            <CheckCircle2 size={19} />
            <span>
              No common warning patterns were detected by this basic check.
            </span>
          </div>
        ) : (
          <div className="indicator-list">
            {result.indicators.map((indicator, index) => (
              <div
                className="indicator-item"
                key={`${indicator.label}-${index}`}
              >
                <div className={`indicator-icon ${indicator.severity}`}>
                  {indicator.severity === "high" ? (
                    <AlertCircle size={17} />
                  ) : indicator.severity === "medium" ? (
                    <AlertTriangle size={17} />
                  ) : (
                    <Info size={17} />
                  )}
                </div>

                <div className="indicator-copy">
                  <div className="indicator-title-row">
                    <strong>{indicator.label}</strong>
                    <span>+{indicator.points}</span>
                  </div>

                  <p>{indicator.explanation}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <section className="indicators-section">
        <h3>Recommended next steps</h3>

        <div className="panel" style={{ padding: "15px", marginTop: "12px" }}>
          <p
            style={{
              color: "var(--muted)",
              fontSize: "11px",
              lineHeight: 1.6,
              marginTop: 0,
            }}
          >
            Use these suggestions as a safety checklist for this result.
          </p>

          <ul
            style={{
              paddingLeft: "20px",
              marginBottom: 0,
              color: "#c4d0df",
              fontSize: "11px",
              lineHeight: 1.9,
            }}
          >
            {guidance.actions.map((action, index) => (
              <li key={index} style={{ marginBottom: "7px" }}>
                {action}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <div className="safety-note">
        <Shield size={19} />

        <div>
          <strong>Important safety note</strong>
          <p>
            {result.safetyNote ||
              "This is an educational heuristic, not an antivirus scan or a live threat-intelligence check. A high score does not prove a website is malicious, and a low score does not guarantee safety. Verify through official channels before sharing information or making payments."}
          </p>
        </div>
      </div>

      <div className="report-actions">
        <button
          className="secondary-button"
          type="button"
          onClick={() => exportRiskReport(result)}
        >
          <Download size={17} />
          Download PDF Report
        </button>
      </div>
    </section>
  );
}

function MailIcon() {
  return <ExternalLink size={23} />;
}

function App() {
  const [activeTab, setActiveTab] = useState("URL Scanner");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState(readHistory);
  const [mobileMenu, setMobileMenu] = useState(false);
  const [error, setError] = useState("");
  const [isChecking, setIsChecking] = useState(false);

  const [historySearch, setHistorySearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("All");
  const [historySort, setHistorySort] = useState("newest");

  useEffect(() => {
    try {
      localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history)
      );
    } catch (storageError) {
      console.warn(
        "PhishCheck could not save scan history in this browser.",
        storageError
      );
    }
  }, [history]);

  const filteredHistory = useMemo(() => {
    const searchTerm = historySearch.trim().toLowerCase();

    return history
      .filter((item) => {
        const matchesSearch =
          !searchTerm ||
          getHistorySearchText(item).includes(searchTerm);

        const matchesRisk =
          riskFilter === "All" || item.risk === riskFilter;

        return matchesSearch && matchesRisk;
      })
      .sort((a, b) => {
        const dateA = new Date(a.scannedAt).getTime() || 0;
        const dateB = new Date(b.scannedAt).getTime() || 0;

        return historySort === "oldest"
          ? dateA - dateB
          : dateB - dateA;
      });
  }, [history, historySearch, riskFilter, historySort]);

  const saveToHistory = (scan) => {
    const historyItem = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      url: scan.url,
      type: scan.type,
      risk: scan.risk,
      score: scan.score,
      scannedAt: scan.scannedAt,
      indicators: scan.indicators,
      submittedContent:
        scan.type === "MESSAGE"
          ? (scan.submittedContent || "").slice(0, HISTORY_MESSAGE_PREVIEW)
          : scan.submittedContent,
      normalizedUrl: scan.normalizedUrl || "",
      safetyNote: scan.safetyNote || "",
    };

    setHistory((previous) =>
      [historyItem, ...previous].slice(0, MAX_HISTORY)
    );
  };

  const handleAnalyzeUrl = async (event) => {
    event.preventDefault();
    setError("");

    let analysis = normalizeAnalysis(
      analyzeUrl(url),
      "URL"
    );

    if (analysis.error) {
      setResult(null);
      setError(analysis.error);
      return;
    }

    if (linkCheckEnabled) {
      setIsChecking(true);

      const check = await checkLink(analysis.normalizedUrl);
      analysis = normalizeAnalysis(applyLinkCheck(analysis, check), "URL");

      setIsChecking(false);
    }

    setResult(analysis);
    saveToHistory(analysis);
  };

  const handleAnalyzeMessage = (event) => {
    event.preventDefault();
    setError("");

    const analysis = normalizeAnalysis(
      analyzeMessage(message),
      "MESSAGE"
    );

    if (analysis.error) {
      setResult(null);
      setError(analysis.error);
      return;
    }

    setResult(analysis);
    saveToHistory(analysis);
  };

  const clearHistory = () => {
    const confirmed = window.confirm(
      "Are you sure you want to clear all saved scan history?"
    );

    if (confirmed) {
      setHistory([]);
    }
  };

  const deleteHistoryItem = (id) => {
    setHistory((previous) =>
      previous.filter((item) => item.id !== id)
    );
  };

  const openHistoryItem = (item) => {
    let restoredResult;

    if (Array.isArray(item.indicators)) {
      restoredResult = normalizeAnalysis(
        {
          ...item,
          indicators: item.indicators,
        },
        item.type === "MESSAGE" ? "MESSAGE" : "URL"
      );
    } else {
      // Older saved entries only contain basic URL history.
      restoredResult = normalizeAnalysis(
        analyzeUrl(item.url),
        "URL"
      );
    }

    if (restoredResult?.error) {
      setError(restoredResult.error);
      return;
    }

    setResult(restoredResult);
    setError("");

    if (restoredResult.type === "MESSAGE") {
      setMessage(restoredResult.submittedContent || "");
      setActiveTab("Message Analyzer");
    } else {
      setUrl(restoredResult.url || item.url);
      setActiveTab("URL Scanner");
    }

    setMobileMenu(false);
  };

  const navigation = [
    { name: "Dashboard", icon: Home },
    { name: "URL Scanner", icon: Search },
    { name: "Message Analyzer", icon: FileSearch },
    { name: "Scan History", icon: History },
    { name: "Learning Center", icon: BookOpen },
  ];

  // Opens a quiz scenario in the matching tool so people can see how
  // PhishCheck judges it.
  const tryQuizItem = (question) => {
    setResult(null);
    setError("");
    setMobileMenu(false);

    if (question.kind === "link") {
      setUrl(question.content);
      setActiveTab("URL Scanner");
    } else {
      setMessage(question.content);
      setActiveTab("Message Analyzer");
    }
  };

  const changeTab = (tab) => {
    setActiveTab(tab);
    setResult(null);
    setError("");
    setMobileMenu(false);
  };

  return (
    <div className="app-shell">
      <aside
        className={`sidebar ${
          mobileMenu ? "sidebar-open" : ""
        }`}
      >
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>
            <h1>PhishCheck</h1>
            <span>SECURITY AWARENESS</span>
          </div>

          <button
            className="mobile-close"
            onClick={() => setMobileMenu(false)}
            aria-label="Close menu"
          >
            <X size={20} />
          </button>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.name}
                className={`nav-item ${
                  activeTab === item.name ? "active" : ""
                }`}
                onClick={() => changeTab(item.name)}
              >
                <Icon size={19} />

                <span>{item.name}</span>

                {item.name === "Scan History" &&
                  history.length > 0 && (
                    <span className="nav-count">
                      {history.length}
                    </span>
                  )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span className="status-dot" />

            <div>
              <strong>Local analysis active</strong>
              <small>Your URLs are not opened</small>
            </div>
          </div>

          <div className="profile">
            <div className="avatar">DP</div>

            <div>
              <strong>Don Philip</strong>
              <small>Security enthusiast</small>
            </div>
          </div>
        </div>
      </aside>

      {mobileMenu && (
        <button
          className="mobile-overlay"
          onClick={() => setMobileMenu(false)}
          aria-label="Close navigation"
        />
      )}

      <main className="main-content">
        <header className="topbar">
          <button
            className="mobile-menu-button"
            onClick={() => setMobileMenu(true)}
            aria-label="Open menu"
          >
            <Menu size={21} />
          </button>

          <div className="breadcrumb">
            Workspace <span>/</span>{" "}
            <strong>{activeTab}</strong>
          </div>

          <div className="topbar-right">
            <span className="protection-status">
              <span className="status-dot" />
              Protection tools active
            </span>

            <div className="topbar-avatar">DP</div>
          </div>
        </header>

        <div className="page-content">
          {activeTab === "Dashboard" && (
            <>
              <section className="welcome-section">
                <div>
                  <span className="eyebrow">
                    SECURITY WORKSPACE
                  </span>

                  <h2>
                    Stay one step ahead of online threats.
                  </h2>

                  <p>
                    Check suspicious links, review messages, and build safer
                    digital habits.
                  </p>
                </div>

                <div className="welcome-shield">
                  <ShieldCheck size={54} />
                </div>
              </section>

              <div className="dashboard-stats">
                <div className="stat-card">
                  <div className="stat-icon">
                    <History size={20} />
                  </div>

                  <span>Saved scans</span>
                  <strong>{history.length}</strong>
                  <small>Stored in this browser</small>
                </div>

                <div className="stat-card">
                  <div className="stat-icon">
                    <ShieldCheck size={20} />
                  </div>

                  <span>Analysis mode</span>
                  <strong>Local</strong>
                  <small>No links are opened</small>
                </div>

                <div className="stat-card">
                  <div className="stat-icon">
                    <Activity size={20} />
                  </div>

                  <span>History limit</span>
                  <strong>{MAX_HISTORY}</strong>
                  <small>Most recent scans</small>
                </div>
              </div>

              <section className="section-block">
                <div className="section-heading">
                  <div>
                    <h2>Protection tools</h2>
                    <p>
                      Choose a tool to start checking suspicious content.
                    </p>
                  </div>
                </div>

                <div className="tool-grid">
                  <button
                    className="tool-card"
                    onClick={() => changeTab("URL Scanner")}
                  >
                    <div className="tool-icon">
                      <Link2 size={23} />
                    </div>

                    <h3>URL Scanner</h3>

                    <p>
                      Inspect web addresses for common phishing indicators.
                    </p>

                    <span>
                      Open scanner <ArrowRight size={15} />
                    </span>
                  </button>

                  <button
                    className="tool-card"
                    onClick={() => changeTab("Message Analyzer")}
                  >
                    <div className="tool-icon">
                      <FileSearch size={23} />
                    </div>

                    <h3>Message Analyzer</h3>

                    <p>
                      Review suspicious messages for social-engineering
                      patterns.
                    </p>

                    <span>
                      Analyze message <ArrowRight size={15} />
                    </span>
                  </button>

                  <button
                    className="tool-card"
                    onClick={() => changeTab("Scan History")}
                  >
                    <div className="tool-icon">
                      <History size={23} />
                    </div>

                    <h3>Scan History</h3>

                    <p>
                      Review your recent URL and message checks.
                    </p>

                    <span>
                      View history <ArrowRight size={15} />
                    </span>
                  </button>
                </div>
              </section>
            </>
          )}

          {activeTab === "URL Scanner" && (
            <>
              <section className="page-heading">
                <div>
                  <span className="eyebrow">
                    ONLINE SAFETY WORKSPACE
                  </span>

                  <h2>URL Scanner</h2>

                  <p>
                    Identify suspicious patterns and make safer decisions
                    online.
                  </p>
                </div>
              </section>

              <div className="scanner-layout">
                <section className="panel scanner-panel">
                  <div className="panel-heading">
                    <div className="panel-icon">
                      <Search size={20} />
                    </div>

                    <div>
                      <h3>Check a suspicious URL</h3>
                      <p>
                        Paste a web address below to inspect it for common
                        phishing indicators.
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleAnalyzeUrl}>
                    <label htmlFor="url-input">
                      Website address
                    </label>

                    <div className="url-input-wrap">
                      <Link2 size={19} />

                      <input
                        id="url-input"
                        type="text"
                        value={url}
                        onChange={(event) =>
                          setUrl(event.target.value)
                        }
                        placeholder="https://example.com"
                        autoComplete="off"
                        maxLength={MAX_URL_LENGTH + 1}
                      />
                    </div>

                    {error && (
                      <p className="form-error">{error}</p>
                    )}

                    <button
                      className="primary-button"
                      type="submit"
                      disabled={isChecking}
                    >
                      <Search size={18} />
                      {isChecking ? "Checking..." : "Analyze URL"}
                    </button>
                  </form>

                  <p className="local-note">
                    <ShieldCheck size={15} />
                    {linkCheckEnabled
                      ? "The address is checked locally and also sent, without any login details, to online threat-list services through our server. The link is never opened."
                      : "Analysis runs locally in your browser. The link will not be opened."}
                  </p>
                </section>

                <aside className="panel tips-panel">
                  <div className="tips-title">
                    <Shield size={19} />
                    <h3>Before you click</h3>
                  </div>

                  <ul>
                    <li>Check the spelling of the domain name.</li>
                    <li>Be careful with shortened links.</li>
                    <li>
                      Never share passwords or OTP codes through a link.
                    </li>
                    <li>
                      Verify unexpected messages through official channels.
                    </li>
                  </ul>

                  <div className="tips-footer">
                    <Info size={16} />
                    <span>
                      A familiar logo does not prove a website is genuine.
                    </span>
                  </div>
                </aside>
              </div>

              <RiskReport result={result} />
            </>
          )}

          {activeTab === "Message Analyzer" && (
            <>
              <section className="page-heading">
                <div>
                  <span className="eyebrow">
                    SOCIAL ENGINEERING CHECK
                  </span>

                  <h2>Message Analyzer</h2>

                  <p>
                    Review suspicious emails, SMS messages, and chat messages.
                  </p>
                </div>
              </section>

              <section className="panel message-panel">
                <div className="panel-heading">
                  <div className="panel-icon">
                    <FileSearch size={20} />
                  </div>

                  <div>
                    <h3>Analyze a suspicious message</h3>
                    <p>
                      Paste the message below. Avoid including private
                      information or passwords.
                    </p>
                  </div>
                </div>

                <form onSubmit={handleAnalyzeMessage}>
                  <label htmlFor="message-input">
                    Message content
                  </label>

                  <textarea
                    id="message-input"
                    value={message}
                    onChange={(event) =>
                      setMessage(event.target.value)
                    }
                    placeholder="Paste the suspicious email, SMS, or chat message here..."
                    rows={7}
                    maxLength={MAX_MESSAGE_LENGTH + 1}
                  />

                  {error && (
                    <p className="form-error">{error}</p>
                  )}

                  <button
                    className="primary-button"
                    type="submit"
                  >
                    <FileSearch size={18} />
                    Analyze message
                  </button>
                </form>

                <p className="local-note">
                  <ShieldCheck size={15} />
                  Message analysis runs locally. Your text is not sent to a
                  server.
                </p>
              </section>

              <RiskReport result={result} />
            </>
          )}

          {activeTab === "Scan History" && (
            <>
              <section className="page-heading history-heading">
                <div>
                  <span className="eyebrow">
                    YOUR RECENT ACTIVITY
                  </span>

                  <h2>Scan History</h2>

                  <p>
                    Review your last {MAX_HISTORY} URL and message scans saved
                    in this browser. Only a short preview of each message is
                    kept.
                  </p>
                </div>

                {history.length > 0 && (
                  <button
                    className="secondary-button danger-button"
                    onClick={clearHistory}
                  >
                    <Trash2 size={17} />
                    Clear history
                  </button>
                )}
              </section>

              <section className="panel history-panel">
                {history.length === 0 ? (
                  <div className="empty-history">
                    <div className="empty-history-icon">
                      <History size={30} />
                    </div>

                    <h3>No scan history yet</h3>

                    <p>
                      Your URL and message scans will appear here after
                      analysis.
                    </p>

                    <button
                      className="primary-button"
                      onClick={() => changeTab("URL Scanner")}
                    >
                      Scan a URL <ArrowRight size={17} />
                    </button>
                  </div>
                ) : (
                  <>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
                        gap: "12px",
                        marginBottom: "20px",
                      }}
                    >
                      <div>
                        <label
                          htmlFor="history-search"
                          style={{ display: "block", marginBottom: "7px" }}
                        >
                          Search scans
                        </label>

                        <div className="url-input-wrap">
                          <Search size={18} />

                          <input
                            id="history-search"
                            type="search"
                            placeholder="Search URL or message..."
                            value={historySearch}
                            onChange={(event) =>
                              setHistorySearch(event.target.value)
                            }
                          />
                        </div>
                      </div>

                      <div>
                        <label
                          htmlFor="risk-filter"
                          style={{ display: "block", marginBottom: "7px" }}
                        >
                          Filter by risk
                        </label>

                        <select
                          id="risk-filter"
                          value={riskFilter}
                          onChange={(event) =>
                            setRiskFilter(event.target.value)
                          }
                          style={{
                            width: "100%",
                            minHeight: "45px",
                            padding: "10px",
                            borderRadius: "9px",
                            border: "1px solid var(--border, #26394c)",
                            background: "var(--panel, #101f30)",
                            color: "inherit",
                          }}
                        >
                          <option value="All">All risk levels</option>
                          <option value="High">High risk</option>
                          <option value="Moderate">Moderate risk</option>
                          <option value="Low">Low risk</option>
                        </select>
                      </div>

                      <div>
                        <label
                          htmlFor="history-sort"
                          style={{ display: "block", marginBottom: "7px" }}
                        >
                          Sort by date
                        </label>

                        <select
                          id="history-sort"
                          value={historySort}
                          onChange={(event) =>
                            setHistorySort(event.target.value)
                          }
                          style={{
                            width: "100%",
                            minHeight: "45px",
                            padding: "10px",
                            borderRadius: "9px",
                            border: "1px solid var(--border, #26394c)",
                            background: "var(--panel, #101f30)",
                            color: "inherit",
                          }}
                        >
                          <option value="newest">Newest first</option>
                          <option value="oldest">Oldest first</option>
                        </select>
                      </div>
                    </div>

                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: "8px",
                        marginBottom: "15px",
                      }}
                    >
                      <span style={{ color: "var(--muted)", fontSize: "12px" }}>
                        Showing {filteredHistory.length} of {history.length} saved scans
                      </span>

                      {(historySearch || riskFilter !== "All") && (
                        <button
                          type="button"
                          className="history-open-button"
                          onClick={() => {
                            setHistorySearch("");
                            setRiskFilter("All");
                          }}
                        >
                          Reset filters
                        </button>
                      )}
                    </div>

                    {filteredHistory.length === 0 ? (
                      <div className="empty-history">
                        <div className="empty-history-icon">
                          <Search size={27} />
                        </div>

                        <h3>No matching scans</h3>

                        <p>
                          Try another search term or change the selected risk
                          level.
                        </p>

                        <button
                          className="secondary-button"
                          onClick={() => {
                            setHistorySearch("");
                            setRiskFilter("All");
                          }}
                        >
                          Reset search and filters
                        </button>
                      </div>
                    ) : (
                      <>
                        <div className="history-table-header">
                          <span>Scanned content</span>
                          <span>Risk level</span>
                          <span>Score</span>
                          <span>Date scanned</span>
                          <span>Actions</span>
                        </div>

                        <div className="history-list">
                          {filteredHistory.map((item) => (
                            <div
                              className="history-row"
                              key={item.id}
                            >
                              <div className="history-url">
                                <div className="history-link-icon">
                                  {item.type === "MESSAGE" ? (
                                    <FileSearch size={17} />
                                  ) : (
                                    <Link2 size={17} />
                                  )}
                                </div>

                                <div>
                                  <strong>
                                    {item.type === "MESSAGE"
                                      ? "Message analysis"
                                      : item.url}
                                  </strong>

                                  <small>
                                    {item.type === "MESSAGE"
                                      ? (item.submittedContent || "").slice(0, 65) +
                                        ((item.submittedContent || "").length > 65
                                          ? "..."
                                          : "")
                                      : `${getIndicatorCount(item)} indicator(s) detected`}
                                  </small>
                                </div>
                              </div>

                              <div>
                                <span
                                  className={`risk-badge small ${item.risk.toLowerCase()}`}
                                >
                                  {item.risk}
                                </span>
                              </div>

                              <strong className="history-score">
                                {item.score}/100
                              </strong>

                              <span className="history-date">
                                {new Date(item.scannedAt).toLocaleString()}
                              </span>

                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "7px",
                                }}
                              >
                                <button
                                  className="history-open-button"
                                  onClick={() => openHistoryItem(item)}
                                  title="Open saved report"
                                  aria-label="Open saved report"
                                >
                                  <ExternalLink size={17} />
                                </button>

                                <button
                                  className="history-open-button"
                                  onClick={() => deleteHistoryItem(item.id)}
                                  title="Delete this scan"
                                  aria-label="Delete this scan"
                                >
                                  <Trash2 size={17} />
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    <p className="history-footnote">
                      <Info size={15} />
                      History is stored only in this browser. Clearing browser
                      site data may remove it. Saved message scans may contain
                      the text you submitted, so avoid entering passwords or
                      other private information.
                    </p>
                  </>
                )}
              </section>
            </>
          )}

          {activeTab === "Learning Center" && (
            <>
              <section className="page-heading">
                <div>
                  <span className="eyebrow">
                    LEARN · RECOGNIZE · PROTECT
                  </span>

                  <h2>Learning Center</h2>

                  <p>
                    Learn how to recognize common online threats and protect
                    your information.
                  </p>
                </div>
              </section>

              <div className="lesson-grid">
                <article className="lesson-card">
                  <div className="lesson-icon">
                    <Link2 size={23} />
                  </div>

                  <span className="lesson-category">
                    PHISHING BASICS
                  </span>

                  <h3>How to recognize a phishing link</h3>

                  <p>
                    Check the actual domain, watch for misspellings, and be
                    cautious of links that ask for sensitive information.
                  </p>
                </article>

                <article className="lesson-card">
                  <div className="lesson-icon">
                    <MailIcon />
                  </div>

                  <span className="lesson-category">
                    EMAIL SAFETY
                  </span>

                  <h3>Spot suspicious messages</h3>

                  <p>
                    Unexpected attachments, pressure, unusual requests, and
                    unfamiliar senders deserve careful attention.
                  </p>
                </article>

                <article className="lesson-card">
                  <div className="lesson-icon">
                    <ShieldAlert size={23} />
                  </div>

                  <span className="lesson-category">
                    ACCOUNT SECURITY
                  </span>

                  <h3>Protect your accounts</h3>

                  <p>
                    Use unique passwords, enable multi-factor authentication,
                    and never share one-time verification codes.
                  </p>
                </article>

                <article className="lesson-card">
                  <div className="lesson-icon">
                    <AlertTriangle size={23} />
                  </div>

                  <span className="lesson-category">
                    SCAM AWARENESS
                  </span>

                  <h3>Recognize social engineering</h3>

                  <p>
                    Scammers may impersonate trusted organizations or create
                    urgency to influence your decisions.
                  </p>
                </article>
              </div>

              <div className="learn-extras">
                <PhishingQuiz onTryIt={tryQuizItem} />
                <VerifyChecklist />
              </div>
            </>
          )}

          <footer className="app-footer">
            <span>© 2026 PhishCheck</span>
            <span>Built for safer digital habits</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

export default App;
