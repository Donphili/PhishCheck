// Measures how well the LOCAL checks (securityEngine.js) do on real, current
// phishing links. Run with:  npm run evaluate
//
// The phishing links come from the OpenPhish community feed, downloaded fresh
// each time and never saved in the repo. That feed is licensed for
// non-commercial use only, so use this script for research and testing.
import fs from "node:fs";
import { analyzeUrl } from "../src/securityEngine.js";

const FEED =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";

const legit = fs
  .readFileSync(new URL("./legit-sites.txt", import.meta.url), "utf8")
  .split("\n")
  .map((line) => line.trim())
  .filter(Boolean);

const response = await fetch(FEED);

if (!response.ok) {
  console.error(`Could not download the feed (HTTP ${response.status}).`);
  process.exit(1);
}

const phishing = (await response.text())
  .split("\n")
  .map((line) => line.trim())
  .filter(Boolean);

const flagged = (url) => {
  const result = analyzeUrl(url);

  return !result.error && result.score >= 30;
};

const caught = phishing.filter(flagged).length;
const falseAlarms = legit.filter(flagged);

console.log(`Real phishing links tested : ${phishing.length}`);
console.log(
  `Flagged Moderate or High   : ${caught} (${((100 * caught) / phishing.length).toFixed(1)}%)`
);
console.log(`Legitimate sites tested    : ${legit.length}`);
console.log(`Wrongly flagged            : ${falseAlarms.length}`);

for (const url of falseAlarms) console.log(`   false alarm: ${url}`);

console.log(
  "\nThe remaining phishing links are what the online threat lists are for."
);
