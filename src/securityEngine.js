
const MAX_URL_LENGTH = 2048;
const MAX_MESSAGE_LENGTH = 10000;

const trustedBrands = {
  google: ["google.com"],
  microsoft: ["microsoft.com", "live.com", "outlook.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.co.uk"],
  paypal: ["paypal.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  netflix: ["netflix.com"],
  linkedin: ["linkedin.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  yahoo: ["yahoo.com"],
  whatsapp: ["whatsapp.com"],
  binance: ["binance.com"],
};

const shortenerDomains = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "shorturl.at",
  "ow.ly",
  "rebrand.ly",
  "buff.ly",
];

const confusables = {
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  х: "x",
  у: "y",
  і: "i",
  ј: "j",
  Α: "a",
  Β: "b",
  Ε: "e",
  Ζ: "z",
  Η: "h",
  Ι: "i",
  Κ: "k",
  Μ: "m",
  Ν: "n",
  Ο: "o",
  Ρ: "p",
  Τ: "t",
  Χ: "x",
};

export function getRiskLevel(score) {
  if (score >= 60) return "High";
  if (score >= 30) return "Moderate";
  return "Low";
}

function hostnameMatchesDomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function isIPv4(hostname) {
  const parts = hostname.split(".");

  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;

    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

function isIPAddress(hostname) {
  const cleanHost = hostname.replace(/^\[|\]$/g, "");

  return (
    isIPv4(cleanHost) ||
    (cleanHost.includes(":") && /^[0-9a-f:]+$/i.test(cleanHost))
  );
}

function normalizeLookalikeText(value) {
  return value
    .normalize("NFKC")
    .split("")
    .map((character) => confusables[character] || character)
    .join("")
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/rn/g, "m");
}

function decodePunycodeLabel(label) {
  if (!label.toLowerCase().startsWith("xn--")) return label;

  const input = label.slice(4);
  const output = [];
  const base = 36;
  const tmin = 1;
  const tmax = 26;

  let n = 128;
  let i = 0;
  let bias = 72;

  const delimiterIndex = input.lastIndexOf("-");

  if (delimiterIndex >= 0) {
    for (const character of input.slice(0, delimiterIndex)) {
      output.push(character.charCodeAt(0));
    }
  }

  let index = delimiterIndex >= 0 ? delimiterIndex + 1 : 0;

  function digitToValue(character) {
    const code = character.toLowerCase().charCodeAt(0);

    if (code >= 48 && code <= 57) return code - 22;
    if (code >= 97 && code <= 122) return code - 97;

    return base;
  }

  function adapt(delta, points, firstTime) {
    let adjusted = firstTime
      ? Math.floor(delta / 700)
      : Math.floor(delta / 2);

    adjusted += Math.floor(adjusted / points);

    let k = 0;

    while (adjusted > Math.floor(((base - tmin) * tmax) / 2)) {
      adjusted = Math.floor(adjusted / (base - tmin));
      k += base;
    }

    return (
      k +
      Math.floor(((base - tmin + 1) * adjusted) / (adjusted + 38))
    );
  }

  try {
    while (index < input.length) {
      const oldI = i;
      let weight = 1;

      for (let k = base; ; k += base) {
        if (index >= input.length) return label;

        const digit = digitToValue(input[index++]);

        if (digit >= base) return label;

        i += digit * weight;

        const threshold =
          k <= bias
            ? tmin
            : k >= bias + tmax
              ? tmax
              : k - bias;

        if (digit < threshold) break;

        weight *= base - threshold;
      }

      const points = output.length + 1;

      bias = adapt(i - oldI, points, oldI === 0);
      n += Math.floor(i / points);
      i %= points;

      if (n > 0x10ffff) return label;

      output.splice(i, 0, n);
      i += 1;
    }

    return String.fromCodePoint(...output);
  } catch {
    return label;
  }
}

function decodeHostname(hostname) {
  return hostname
    .split(".")
    .map(decodePunycodeLabel)
    .join(".");
}

function findBrandInHostname(hostname) {
  const labels = hostname.split(".");

  for (const [brand, officialDomains] of Object.entries(trustedBrands)) {
    const isOfficial = officialDomains.some((domain) =>
      hostnameMatchesDomain(hostname, domain)
    );

    if (isOfficial) continue;

    for (const label of labels) {
      const normalized = normalizeLookalikeText(label);

      if (
        normalized.includes(brand) &&
        normalized !== label.toLowerCase()
      ) {
        return {
          brand,
          officialDomains,
          lookalike: true,
          originalLabel: label,
        };
      }

      if (label.toLowerCase().includes(brand)) {
        return {
          brand,
          officialDomains,
          lookalike: false,
          originalLabel: label,
        };
      }
    }
  }

  return null;
}

function findOfficialDomainText(hostname, officialDomains) {
  const parts = hostname.split(".");

  return officialDomains.find((domain) => {
    const domainParts = domain.split(".");

    for (
      let start = 0;
      start <= parts.length - domainParts.length;
      start += 1
    ) {
      if (
        parts.slice(start, start + domainParts.length).join(".") === domain
      ) {
        return true;
      }
    }

    return false;
  });
}

function addIndicator(indicators, label, points, severity, explanation) {
  indicators.push({
    label,
    points,
    severity,
    explanation,
  });
}

export function analyzeUrl(input) {
  const trimmedInput = String(input || "").trim();

  if (!trimmedInput) {
    return {
      error: "Please enter a website address before analyzing.",
    };
  }

  if (trimmedInput.length > MAX_URL_LENGTH) {
    return {
      error: `The address is too long. Maximum length is ${MAX_URL_LENGTH} characters.`,
    };
  }

  if (/[\u0000-\u001F\u007F\s]/.test(trimmedInput)) {
    return {
      error:
        "The address contains spaces or unsupported control characters. Check the URL and try again.",
    };
  }

  let parsedUrl;

  try {
    const hasWebScheme = /^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(
      trimmedInput
    );

    parsedUrl = new URL(
      hasWebScheme ? trimmedInput : `https://${trimmedInput}`
    );
  } catch {
    return {
      error:
        "This address does not appear to be a valid URL. Check it and try again.",
    };
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return {
      error: "Only HTTP and HTTPS website addresses can be analyzed.",
    };
  }

  if (!parsedUrl.hostname) {
    return {
      error: "A valid website hostname could not be found in this address.",
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const fullUrl = parsedUrl.href;
  const indicators = [];

  if (isIPAddress(hostname)) {
    addIndicator(
      indicators,
      "IP address used as website",
      25,
      "high",
      "The website uses a numerical IP address instead of a normal domain name. Some legitimate services use IP addresses, but unexpected IP-based links deserve extra care."
    );
  }

  if (parsedUrl.username || parsedUrl.password) {
    addIndicator(
      indicators,
      "Unusual URL credentials",
      25,
      "high",
      "The address contains username or password information before the hostname. This can make a destination confusing and is a warning sign worth investigating."
    );
  }

  if (hostname.split(".").some((label) => label.startsWith("xn--"))) {
    const decodedHostname = decodeHostname(hostname);

    addIndicator(
      indicators,
      "Encoded international domain",
      12,
      "medium",
      `The hostname contains Punycode encoding. Decoded hostname: ${decodedHostname}. Internationalized domains are not automatically malicious, but visually similar characters can be deceptive.`
    );

    const normalizedDecoded = normalizeLookalikeText(decodedHostname);

    for (const [brand, officialDomains] of Object.entries(trustedBrands)) {
      const isOfficial = officialDomains.some((domain) =>
        hostnameMatchesDomain(hostname, domain)
      );

      if (normalizedDecoded.includes(brand) && !isOfficial) {
        addIndicator(
          indicators,
          "Possible internationalized brand impersonation",
          35,
          "high",
          `The decoded hostname resembles the ${brand} brand but does not use its listed official domain.`
        );

        break;
      }
    }
  }

  const hostnameParts = hostname.split(".");
  const brandMatch = findBrandInHostname(hostname);

  if (brandMatch) {
    const embeddedOfficialDomain = findOfficialDomainText(
      hostname,
      brandMatch.officialDomains
    );

    if (brandMatch.lookalike) {
      addIndicator(
        indicators,
        "Possible lookalike brand spelling",
        45,
        "high",
        `The hostname section "${brandMatch.originalLabel}" resembles "${brandMatch.brand}" after common character substitutions. Check the spelling and actual domain carefully.`
      );
    } else if (embeddedOfficialDomain) {
      // Increased from 45 to 55 to better identify deceptive domains.
      addIndicator(
        indicators,
        "Official domain text inside an untrusted hostname",
        55,
        "high",
        `The hostname contains "${embeddedOfficialDomain}", but the complete hostname is not that organization's official domain.`
      );
    } else {
      addIndicator(
        indicators,
        `Possible ${brandMatch.brand} impersonation`,
        55,
        "high",
        `The hostname contains the name "${brandMatch.brand}" but does not match the listed official domain patterns. Verify the address using the organization's official website.`
      );
    }

    const subdomainParts = hostnameParts.slice(
      0,
      Math.max(0, hostnameParts.length - 2)
    );

    const brandInSubdomain = subdomainParts.some(
      (part) =>
        part.includes(brandMatch.brand) ||
        normalizeLookalikeText(part).includes(brandMatch.brand)
    );

    if (
      brandInSubdomain &&
      !brandMatch.lookalike &&
      !embeddedOfficialDomain
    ) {
      addIndicator(
        indicators,
        "Brand name in subdomain",
        15,
        "high",
        `The name "${brandMatch.brand}" appears before the final hostname sections. That text does not establish who owns the actual domain.`
      );
    }
  }

  if (hostnameParts.length >= 5) {
    addIndicator(
      indicators,
      "Unusually long subdomain structure",
      10,
      "medium",
      "The hostname contains many sections. This can make the real destination harder to recognize."
    );
  }

  if (
    shortenerDomains.some((domain) =>
      hostnameMatchesDomain(hostname, domain)
    )
  ) {
    addIndicator(
      indicators,
      "URL shortening service",
      10,
      "medium",
      "Shortened links hide their final destination. Verify the destination independently before visiting."
    );
  }

  if (
    /\b(login|verify|password|account|banking|wallet|secure|update|confirm|signin|authentication|support)\b/i.test(
      `${hostname}${parsedUrl.pathname}${parsedUrl.search}`
    )
  ) {
    addIndicator(
      indicators,
      "Sensitive account-related wording",
      8,
      "low",
      "The address contains words commonly used in account verification and credential requests. These words alone do not prove fraud."
    );
  }

  if (/%[0-9a-f]{2}/i.test(fullUrl)) {
    addIndicator(
      indicators,
      "Encoded URL characters",
      8,
      "low",
      "The address contains percent-encoded characters. Encoding is normal in many URLs, but can sometimes hide confusing text."
    );
  }

  if (parsedUrl.protocol === "http:") {
    addIndicator(
      indicators,
      "Unencrypted HTTP connection",
      8,
      "medium",
      "The address uses HTTP rather than HTTPS. Information sent to the site may not be encrypted. HTTPS alone does not prove that a website is trustworthy."
    );
  }

  if (fullUrl.length > 120) {
    addIndicator(
      indicators,
      "Unusually long web address",
      6,
      "low",
      "Long addresses can make it harder to notice misleading or unexpected sections."
    );
  }

  if (parsedUrl.port && !["80", "443"].includes(parsedUrl.port)) {
    addIndicator(
      indicators,
      "Non-standard website port",
      10,
      "medium",
      "The website uses a port that is less common for normal web browsing. This is not proof of malicious activity."
    );
  }

  if ((hostname.match(/-/g) || []).length >= 3) {
    addIndicator(
      indicators,
      "Multiple hyphens in domain",
      5,
      "low",
      "The domain contains several hyphens. This is not proof of fraud, but deserves a closer look."
    );
  }

  const score = Math.min(
    indicators.reduce((total, item) => total + item.points, 0),
    100
  );

  const riskLevel = getRiskLevel(score);
  const analyzedAt = new Date().toISOString();

  return {
    type: "URL",
    input: trimmedInput,
    url: trimmedInput,
    normalizedUrl: fullUrl,
    hostname,
    score,
    riskLevel,
    risk: riskLevel,
    indicators,
    analyzedAt,
    scannedAt: analyzedAt,
    submittedContent: trimmedInput,
    safetyNote:
      "This assessment uses local heuristic checks only. It does not query live threat-intelligence databases. A low score does not guarantee safety, and a high score does not prove malicious activity.",
  };
}

export function analyzeMessage(input) {
  const submittedContent = String(input || "").trim();

  if (!submittedContent) {
    return {
      error: "Please paste a message before analyzing.",
    };
  }

  if (submittedContent.length > MAX_MESSAGE_LENGTH) {
    return {
      error: `The message is too long. Maximum length is ${MAX_MESSAGE_LENGTH} characters.`,
    };
  }

  const indicators = [];

  const educationalContext =
    /\b(never|don't|do not|avoid|beware|warning|teach|training|learn|recognize|spot|identify|protect against|awareness|example of|phishing awareness)\b/i.test(
      submittedContent
    );

  const directCredentialRequest =
    /\b(send|share|provide|reply with|enter|submit|confirm|tell us|give us)\b.{0,70}\b(password|passcode|otp|one[- ]time password|verification code|pin)\b/i.test(
      submittedContent
    );

  const directFinancialRequest =
    /\b(send|share|provide|reply with|enter|submit|give us|confirm)\b.{0,70}\b(bank details|card number|credit card|debit card|account number|payment details|cvv|security code)\b/i.test(
      submittedContent
    );

  const patterns = [
    {
      label: "Direct request for passwords or verification codes",
      regex:
        /\b(send|share|provide|reply with|enter|submit|confirm|tell us|give us)\b.{0,70}\b(password|passcode|otp|one[- ]time password|verification code|pin)\b/i,
      points: 45,
      severity: "high",
      explanation:
        "The message appears to ask the recipient to provide sensitive login credentials or verification codes. Never share these secrets through unexpected messages.",
      educationalSensitive: true,
    },
    {
      label: "Direct request for financial information",
      regex:
        /\b(send|share|provide|reply with|enter|submit|give us|confirm)\b.{0,70}\b(bank details|card number|credit card|debit card|account number|payment details|cvv|security code)\b/i,
      points: 35,
      severity: "high",
      explanation:
        "The message appears to request sensitive financial information. Verify the request independently before sharing any details.",
      educationalSensitive: true,
    },
    {
      label: "Urgent or threatening language",
      regex:
        /\b(urgent|immediately|act now|right away|final warning|within 24 hours|without delay|as soon as possible)\b/i,
      points: 15,
      severity: "medium",
      explanation:
        "The message creates pressure to act quickly. Scammers often use urgency to discourage careful verification.",
    },
    {
      label: "Prize or unexpected reward",
      regex:
        /\b(you have won|winner|claim your prize|free reward|congratulations|cash prize|claim reward|gift card)\b/i,
      points: 15,
      severity: "medium",
      explanation:
        "The message uses prize or reward language that may be designed to attract attention or encourage a response.",
    },
    {
      label: "Suspicious link or account verification request",
      regex:
        /\b(click here|tap here|verify your account|confirm your account|account verification|follow this link|open this link)\b/i,
      points: 15,
      severity: "medium",
      explanation:
        "The message encourages the recipient to follow a link or verify an account. Check the destination independently before proceeding.",
      educationalSensitive: true,
    },
    {
      label: "Account suspension or closure threat",
      regex:
        /\b(account will be suspended|account suspended|account will be closed|account has been locked|permanently disabled|access will be restricted)\b/i,
      points: 15,
      severity: "medium",
      explanation:
        "The message threatens account suspension or loss of access. This is a common pressure tactic in phishing attempts.",
    },
    {
      label: "Unusual payment method",
      regex:
        /\b(gift cards|gift card|cryptocurrency|bitcoin|wire transfer|western union|moneygram|prepaid card)\b/i,
      points: 20,
      severity: "high",
      explanation:
        "The message mentions payment methods that can be difficult to reverse or trace. Be cautious if someone demands payment this way.",
    },
    {
      label: "Unexpected attachment",
      regex:
        /\b(open the attachment|attached file|download the attachment|enable macros)\b/i,
      points: 15,
      severity: "medium",
      explanation:
        "The message encourages opening or downloading an attachment. Unexpected attachments can contain harmful files.",
    },
    {
      label: "Impersonation language",
      regex:
        /\b(we are from|on behalf of|your bank representative|technical support team|security department)\b/i,
      points: 10,
      severity: "low",
      explanation:
        "The sender uses organizational or authority-related language. Independently verify the sender before trusting the request.",
    },
  ];

  patterns.forEach((pattern) => {
    if (!pattern.regex.test(submittedContent)) return;

    if (educationalContext && pattern.educationalSensitive) return;

    if (
      pattern.label ===
        "Direct request for passwords or verification codes" &&
      !directCredentialRequest
    ) {
      return;
    }

    if (
      pattern.label === "Direct request for financial information" &&
      !directFinancialRequest
    ) {
      return;
    }

    indicators.push({
      label: pattern.label,
      points: pattern.points,
      severity: pattern.severity,
      explanation: pattern.explanation,
    });
  });

  if (
    !directCredentialRequest &&
    /\b(password|passcode|otp|one[- ]time password|verification code|pin)\b/i.test(
      submittedContent
    )
  ) {
    indicators.push({
      label: "Sensitive login information mentioned",
      points: 8,
      severity: "low",
      explanation:
        "The message mentions passwords or verification codes. This mention alone does not prove a phishing attempt, but sensitive login information should always be protected.",
    });
  }

  const score = Math.min(
    indicators.reduce((total, item) => total + item.points, 0),
    100
  );

  const riskLevel = getRiskLevel(score);
  const analyzedAt = new Date().toISOString();

  return {
    type: "MESSAGE",
    input: submittedContent,
    url: "Message analysis",
    submittedContent,
    score,
    riskLevel,
    risk: riskLevel,
    indicators,
    analyzedAt,
    scannedAt: analyzedAt,
    safetyNote:
      "This assessment uses local text-pattern checks. It cannot establish who sent the message or verify whether a request is genuine. Contact the organization through an independently verified channel before taking action.",
  };
}
