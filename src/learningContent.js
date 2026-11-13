// Content for the Learning Center quiz and the "verify safely" checklist.
// All names and web addresses in the scenarios are made up (.example).
// Amounts are in Kuwaiti dinar (KD).

// kind: "message" scenarios can be opened in the Message Analyzer,
// "link" scenarios in the URL Scanner, "none" ones cannot be analyzed here. "context" tells the reader something
// they would know in real life (for example that they just placed an order).
export const quizQuestions = [
  {
    id: "parcel-fee",
    channel: "SMS",
    kind: "message",
    content:
      "KWPost: Your parcel could not be delivered. Pay a 0.750 KD redelivery fee to release it today: http://kwpost-parcel.example/pay",
    isScam: true,
    explanation:
      "Fake delivery fees are one of the most common scams. The amount is small on purpose, so people pay without thinking. The link goes to an unrelated website, and the message pushes you to act today.",
    redFlags: [
      "A fee you were never told about",
      "A link to an unfamiliar website",
      "Pressure to act immediately",
    ],
    action:
      "Do not tap the link. Check the delivery through the courier's official app, or type their website address yourself.",
  },
  {
    id: "bank-alert",
    channel: "SMS",
    kind: "message",
    content:
      "Your card ending 2291 was used for 12.500 KD at a supermarket. If this was not you, call the number on the back of your card.",
    isScam: false,
    explanation:
      "This message only informs you. It contains no link, asks for no code or password, and sends you to the number printed on your own card, which a scammer cannot control.",
    redFlags: [],
    action:
      "If you did not make the purchase, call the number on the back of your card, not any number that arrives by message.",
  },
  {
    id: "remote-job",
    channel: "WhatsApp",
    kind: "message",
    content:
      "Hi! I got your number from a friend. We offer remote work: earn 40 KD per day just by liking videos. No experience needed. Reply YES to start.",
    isScam: true,
    explanation:
      "Task and job scams promise easy money from a stranger. They usually start with small payments to build trust, then ask you to deposit money to unlock bigger earnings, which you never get back.",
    redFlags: [
      "An unrequested job offer from a stranger",
      "Very high pay for almost no work",
      "Moving you into a private chat",
    ],
    action:
      "Do not reply. Block and report the number. A real employer never asks you to pay to start working.",
  },
  {
    id: "account-suspended",
    channel: "Email",
    kind: "message",
    content:
      "Security alert: your Google account will be suspended within 24 hours unless you verify your identity. Verify now: https://accounts-google.com-verify.example/login",
    isScam: true,
    explanation:
      "The real company name is only the start of the address. The part that counts is the domain just before the first single slash, and here that is com-verify.example, which has nothing to do with Google.",
    redFlags: [
      "A deadline and a threat of suspension",
      "A look-alike address that hides the real domain",
      "A request to log in through a link in the email",
    ],
    action:
      "Do not use the link. Open the official app or type the website address yourself, then check for alerts in your account.",
  },
  {
    id: "expected-code",
    channel: "SMS",
    kind: "message",
    context: "You just tried to log in to your own account.",
    content:
      "Your verification code is 482913. It expires in 10 minutes. Never share this code with anyone.",
    isScam: false,
    explanation:
      "You asked for this code a moment ago, and the message asks you to do nothing except type the code into the app you are already using. Codes you did not request are the warning sign.",
    redFlags: [],
    action:
      "Use the code only in the app or website where you asked for it. If a code arrives and you did not ask for one, someone may be trying to get into your account: change your password.",
  },
  {
    id: "bank-security-call",
    channel: "Phone call",
    kind: "message",
    content:
      "This is the bank's security team. We blocked a suspicious transfer from your account. To cancel it, please read us the code we just sent to your phone.",
    isScam: true,
    explanation:
      "The code that was just sent is what lets the caller approve a payment or log in as you. A real bank never asks you to read out a one-time code, a PIN or a password.",
    redFlags: [
      "A caller who contacts you first and creates fear",
      "A request for a one-time code",
      "Pressure to act during the call",
    ],
    action:
      "Hang up. Call your bank back on the number printed on your card or on its official website.",
  },
  {
    id: "lookalike-link",
    channel: "Link",
    kind: "link",
    content: "https://www.paypal.com.account-review.example/signin",
    isScam: true,
    explanation:
      "Read the address from the right side of the first single slash backwards. The real domain here is account-review.example. The words paypal.com are only a sub-name placed in front to fool you.",
    redFlags: [
      "A trusted brand name used as a sub-name",
      "A different real domain after it",
    ],
    action:
      "Never sign in from this link. Type the company's address yourself or use its official app.",
  },
  {
    id: "country-domain",
    channel: "Link",
    kind: "link",
    content: "https://www.google.com.kw/search?q=weather",
    isScam: false,
    explanation:
      "Big companies often run official websites for each country. Here the real domain is google.com.kw, which is Google's site for Kuwait. A name appearing in a link is not suspicious by itself. What matters is where the domain actually ends.",
    redFlags: [],
    action:
      "Learn to read the domain, but do not distrust every link. Check the part just before the first single slash.",
  },
  {
    id: "ceo-invoice",
    channel: "Email",
    kind: "message",
    context: "You work in your company's finance team.",
    content:
      "From: Ahmed (CEO) <ceo.office@mailbox.example>\nPlease process the attached invoice today. Our supplier has changed bank accounts, so use the new details in the file. I am in meetings, do not call me.",
    isScam: true,
    explanation:
      "This is called business email compromise. The scammer pretends to be a boss or supplier, rushes you, changes bank details, and tells you not to check. These scams cost companies large sums.",
    redFlags: [
      "New bank details sent by email",
      "A boss who cannot be called",
      "A free mailbox address instead of the company address",
      "Urgency and authority used together",
    ],
    action:
      "Confirm any change of bank details by phoning a number you already have on file, and follow your company's payment approval process.",
  },
  {
    id: "traffic-fine",
    channel: "SMS",
    kind: "message",
    content:
      "You have an unpaid traffic fine of 25 KD. Pay within 24 hours to avoid a double penalty: http://traffic-fines-pay.example",
    isScam: true,
    explanation:
      "Scammers copy official bodies because people are afraid of fines. Official fines are managed through the authority's own app or website, and they do not send payment links from unknown addresses.",
    redFlags: [
      "A fine with a short deadline and a bigger penalty",
      "A payment link to an unfamiliar website",
      "No details such as a vehicle number or date",
    ],
    action:
      "Check your fines in the authority's official app or on the website address you type yourself. Do not pay through the link.",
  },
  {
    id: "order-update",
    channel: "App notification",
    kind: "message",
    context:
      "You placed a food order in a delivery app ten minutes ago.",
    content:
      "Your order #4821 is on the way. You can follow your driver in the app.",
    isScam: false,
    explanation:
      "It matches something you really did, it contains no link, and it points you back to the app you already use. When a message fits what you were expecting and asks for nothing, it is usually fine.",
    redFlags: [],
    action:
      "If you had not placed an order, ignore it and check your orders inside the app instead.",
  },
  {
    id: "giveaway",
    channel: "Instagram message",
    kind: "message",
    content:
      "Congratulations! You won our giveaway: a brand new phone. Pay only 2 KD shipping to claim it today. Send your card details here.",
    isScam: true,
    explanation:
      "You cannot win a contest you never entered. The small shipping fee is bait: the real goal is your card details, which are then used for larger payments.",
    redFlags: [
      "A prize you did not enter for",
      "A fee to receive a free gift",
      "A request for card details by message",
    ],
    action:
      "Do not send anything. Block and report the account.",
  },
  {
    id: "friend-new-number",
    channel: "WhatsApp",
    kind: "message",
    content:
      "Hey, it's me. I lost my phone and this is my new number. Can you transfer 50 KD to this account for me? I'll pay you back tonight.",
    isScam: true,
    explanation:
      "Scammers copy a profile picture and write as a friend or relative in trouble. They rely on you wanting to help quickly, before you check.",
    redFlags: [
      "A new number and an urgent money request",
      "A reason why they cannot call",
      "A promise to pay back soon",
    ],
    action:
      "Call the person on their old number, or ask a question only they could answer, before sending anything.",
  },
  {
    id: "parking-qr",
    channel: "QR code",
    kind: "none",
    context:
      "You are at a parking machine. A QR sticker on it says Scan to pay. It looks stuck on top of the printed panel.",
    content: "Scan to pay for parking (sticker placed over the original panel)",
    isScam: true,
    explanation:
      "Scammers stick their own QR codes over real ones, so scanning sends your payment, or your card details, to them. A sticker placed on top of printed material is a warning sign.",
    redFlags: [
      "A sticker covering the original panel",
      "A QR code that opens a payment page you did not expect",
    ],
    action:
      "Pay with the official parking app or the machine itself. If the sticker looks tampered with, tell the operator.",
  },
];

export const verifySteps = [
  {
    id: "pause",
    title: "Pause for a moment",
    detail:
      "Scammers want you to act before you think. A real problem with a bank account, parcel or fine does not disappear in ten minutes. Take a breath before you tap, reply or pay.",
  },
  {
    id: "ask",
    title: "Find out what is being asked of you",
    detail:
      "Is the message asking for money, a code, a password, card details, a click or an app installation? These are the requests scammers need. A message that asks for nothing is usually just information.",
  },
  {
    id: "contact",
    title: "Do not use the contact details in the message",
    detail:
      "Do not tap its link, call its number or reply to it. Open the official app yourself, type the website address yourself, or call the number on your card, bill or the organization's own website.",
  },
  {
    id: "link",
    title: "Read the link without opening it",
    detail:
      "The real domain is the part just before the first single slash. paypal.com.account-review.example belongs to account-review.example. Shortened links hide the destination. You can paste a link into the URL Scanner here to see its warning signs. A clean result does not prove a link is safe.",
  },
  {
    id: "second-channel",
    title: "Check with a second channel",
    detail:
      "If a friend, relative or boss asks for money, call them on a number you already have. If a company contacts you, check inside its official app. If it is a work request, ask a colleague in person or by phone.",
  },
  {
    id: "secrets",
    title: "Never share codes, PINs or passwords",
    detail:
      "No genuine bank, government office, delivery company or support team will ask you to read out or send a one-time code, PIN or password. If someone asks, that tells you it is a scam.",
  },
  {
    id: "report",
    title: "Report it and clear it away",
    detail:
      "Report the message to the app or platform, block the sender, and tell friends or colleagues who might get the same message. If it targeted your work, tell your IT or security team.",
  },
];

// Steps for people who already clicked or shared something. Order matters:
// the most urgent steps come first. Advice is deliberately general because
// the right contact differs by bank and country.
export const afterIncident = [
  {
    id: "clicked",
    title: "I tapped a link but entered nothing",
    steps: [
      "Close the page. Do not enter anything and do not download anything it offers.",
      "If your phone or browser asked to install something or allow notifications, deny it. If you did allow, remove it in your settings.",
      "Keep your device updated, and run a security scan if you are worried.",
    ],
  },
  {
    id: "password",
    title: "I entered a password",
    steps: [
      "Go to the real website or app (type the address yourself) and change that password immediately.",
      "Change the password on any other account where you use the same one.",
      "Turn on two-step verification and sign out of all other devices.",
      "Check your email's forwarding rules and recent sign-in activity for anything you do not recognize.",
    ],
  },
  {
    id: "card-or-code",
    title: "I shared card details or a one-time code",
    steps: [
      "Call your bank right now using the number on your card or on its official website. Ask them to block the card and stop any payment in progress.",
      "Ask the bank to review recent transactions and to issue a new card.",
      "Do not wait to see whether something happens. Speed matters most.",
      "Keep screenshots and the message, and report it to the police or the cybercrime reporting channel in your country.",
    ],
  },
  {
    id: "installed",
    title: "I installed an app or gave remote access",
    steps: [
      "Turn off the internet connection (Wi-Fi and mobile data) on the device.",
      "Uninstall the app and remove any permissions or remote access you gave.",
      "From a different, safe device, change your important passwords and call your bank.",
      "Consider a factory reset if you cannot find or remove the app.",
    ],
  },
  {
    id: "sent-money",
    title: "I sent money",
    steps: [
      "Contact your bank or payment provider immediately. Some transfers can be stopped if you act quickly.",
      "Keep every message, receipt and account detail as evidence.",
      "Report it to the police or the cybercrime reporting channel in your country.",
      "Be careful of follow-up scammers who offer to recover your money for a fee. They are usually part of the same scam.",
    ],
  },
];

export function shuffle(items, random = Math.random) {
  const copy = [...items];

  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));

    [copy[i], copy[j]] = [copy[j], copy[i]];
  }

  return copy;
}

export const ROUND_SIZE = 8;

export function buildRound(random = Math.random) {
  const scams = shuffle(quizQuestions.filter((q) => q.isScam), random);
  const genuine = shuffle(quizQuestions.filter((q) => !q.isScam), random);

  // Always include some genuine messages so people do not learn to say
  // "scam" to everything.
  return shuffle(
    [...genuine.slice(0, 3), ...scams.slice(0, ROUND_SIZE - 3)],
    random
  );
}

export function scoreMessage(correct, total) {
  const ratio = correct / total;

  if (ratio === 1) {
    return "Perfect. You spotted every scam and trusted every genuine message correctly.";
  }

  if (ratio >= 0.75) {
    return "Strong result. Review the ones you missed and you will be hard to fool.";
  }

  if (ratio >= 0.5) {
    return "A decent start. Scams are designed to look convincing, so read the explanations carefully.";
  }

  return "Do not worry. These scams fool many people. Go through the explanations and the checklist, then try again.";
}
