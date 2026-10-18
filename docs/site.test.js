// Runs docs/site.js — the file Pages actually serves — against a minimal DOM
// stub, so what it reads from the GitHub API and the URL check it applies are
// asserted instead of assumed.
//
// Why this exists: site.js renders the download table, and no Go test can see
// it. Three failures that all showed up only once the file was actually run:
//
//   1. a `startsWith` URL check accepted
//      ".../releases/download/v9/../../../evil", which resolves to
//      https://github.com/DevCop95/evil
//   2. the SHA-256 column was fetched from github.com/.../releases/download/
//      checksums.txt, which sends no Access-Control-Allow-Origin — every real
//      browser logged "blocked by CORS policy" and the hashes never rendered
//   3. an element id renamed in index.html makes site.js return at its guard,
//      which reads as a passing test and an empty page
//
// (2) is the one a DOM stub alone cannot catch: stubs do not implement CORS.
// So the test asserts the *request budget* instead — exactly one fetch, to the
// only origin that returns CORS headers. That is checkable offline and it is
// the property that actually matters in a browser.
//
// No dependencies and no network: `node docs/site.test.js` in CI, nothing to
// install. The fixtures are trimmed copies of a real
// /repos/DevCop95/pullgoscript/releases/latest response (v2.0.2, published
// 2026-10-17), including its real `digest` fields, so the shapes are the ones
// GitHub actually sends. SITE_TEST_LIVE=1 hits the live API instead; CI never
// does, so a GitHub hiccup cannot turn this gate red.
"use strict";

const fs = require("fs");
const path = require("path");
const assert = require("assert/strict");

const DIR = __dirname;
const SRC = fs.readFileSync(path.join(DIR, "site.js"), "utf8");
const HTML = fs.readFileSync(path.join(DIR, "index.html"), "utf8");

const ORIGIN = "https://github.com";
const ASSET_PATH = "/DevCop95/pullgoscript/releases/download/";
const PREFIX = ORIGIN + ASSET_PATH;
const API = "https://api.github.com/repos/DevCop95/pullgoscript/releases/latest";
// The only origin in this page that answers with Access-Control-Allow-Origin.
// github.com/.../releases/download/... does not, and neither does the CDN it
// redirects to — that is the whole reason the page must not ask them.
const CORS_ORIGIN = "https://api.github.com/";


let checks = 0;
function ok(label, detail) {
  checks++;
  console.log("  ok   " + label + (detail !== undefined ? "  (" + detail + ")" : ""));
}
function eq(label, actual, expected) {
  checks++;
  assert.deepEqual(
    actual,
    expected,
    label +
      "\n         expected: " + JSON.stringify(expected) +
      "\n         actual:   " + JSON.stringify(actual)
  );
  console.log("  ok   " + label);
}

// --- fixtures: real values, not invented ones ----------------------------
// `digest` is what the API returns for each asset. The four values that also
// appear in the published checksums.txt match it exactly, which is what makes
// the column trustworthy: the page is not parsing a file it re-downloads, it
// is quoting GitHub's own record of what it signed the release with.

const RELEASE = {
  tag_name: "v2.0.2",
  published_at: "2026-10-17T13:36:41Z",
  assets: [
    { name: "checksums.txt", size: 428, browser_download_url: PREFIX + "v2.0.2/checksums.txt",
      digest: "sha256:c50ddb6e302151ac17c43f7dae1811d6d0dec2a342f1731ab176bc2f8916057a" },
    { name: "checksums.txt.pem", size: 3268, browser_download_url: PREFIX + "v2.0.2/checksums.txt.pem",
      digest: "sha256:9c53fa9a38fd70d6ad965bc902a72bdced21c5b0a05bea2dbba40676a32b73d5" },
    { name: "checksums.txt.sig", size: 96, browser_download_url: PREFIX + "v2.0.2/checksums.txt.sig",
      digest: "sha256:0be6c93eb5ae7e033f374ef255af3eda613a8314fa1202d33a59d30a9b79d842" },
    { name: "obliteratus_2.0.2_windows_amd64.zip", size: 6131480,
      browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_amd64.zip",
      digest: "sha256:90b2e6e5794ed17892ccded42df81ea74840ca40b50370bd9fc7e117d9cff3c8" },
    { name: "obliteratus_2.0.2_windows_amd64.zip.sbom.json", size: 26548,
      browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_amd64.zip.sbom.json",
      digest: "sha256:ce40c67281c31eb540e8f4639894bf471b110f1fb35136ed413344dd64477c66" },
    { name: "obliteratus_2.0.2_windows_arm64.zip", size: 5622388,
      browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_arm64.zip",
      digest: "sha256:ae47be1d2bbce867b6e5f08de35be2e3d90649ffa8bf9c7bdecc1930cb077160" },
    { name: "obliteratus_2.0.2_windows_arm64.zip.sbom.json", size: 26548,
      browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_arm64.zip.sbom.json",
      digest: "sha256:68b9ab079ed67a5b5dba381ec2cff53f3b9dcf6ebe74de1a57a778d442a3662c" },
  ],
};

// What the browser is allowed to read from a third-party origin. Kept here as
// a plain table so the request-budget assertion is a comparison, not a hope.
const CORS_OK = [CORS_ORIGIN];

// --- the DOM the page would build, plus a trap for unsafe hrefs ----------

let violations = [];

function makeEl(tag) {
  const el = {
    tagName: tag,
    children: [],
    textContent: "",
    className: "",
    hidden: false,
    _href: null,
    appendChild(c) { el.children.push(c); return c; },
    removeChild(c) { el.children = el.children.filter(x => x !== c); return c; },
    get firstChild() { return el.children[0] || null; },
  };
  Object.defineProperty(el, "href", {
    get() { return el._href; },
    set(v) {
      if (v === null || v === undefined) {
        // A real DOM turns `a.href = null` into the string "null" and the link
        // points at /pullgoscript/null. Nothing should ever assign it.
        violations.push("href assigned " + v);
      } else if (String(v).indexOf(PREFIX) !== 0) {
        violations.push("href outside the download path: " + v);
      }
      el._href = v;
    },
  });
  return el;
}

// The ids are read from index.html, not hard-coded: rename one there and
// site.js returns at its guard, which this test reports as an empty table
// rather than a passing run.
const idsInHTML = new Set([...HTML.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));

// Records every URL the page asks for, and flags as a violation anything
// outside api.github.com — a real browser would refuse it, so a stub that
// silently "succeeds" would be hiding the failure. This is scenario 2 of the
// bug list above, encoded.
let corsViolations = [];

async function run(payload, opts) {
  opts = opts || {};
  violations = [];
  corsViolations = [];
  const dom = { "dl-live": makeEl("div"), "dl-status": makeEl("p"), "dl-fallback": makeEl("table") };
  const fetched = [];

  const document = {
    getElementById: id => (idsInHTML.has(id) ? dom[id] || null : null),
    createElement: makeEl,
  };
  const fetch = url => {
    fetched.push(url);
    if (typeof url !== "string" || !CORS_OK.some(ok => url.indexOf(ok) === 0)) {
      corsViolations.push(String(url));
      // Fail the way a browser fails: opaque, no data. The test then has to
      // notice that the page went empty.
      return Promise.reject(new TypeError("Failed to fetch (CORS)"));
    }
    if (opts.httpStatus) {
      return Promise.resolve({ ok: false, status: opts.httpStatus, json: () => Promise.reject(new Error("no body")) });
    }
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(payload) });
  };

  new Function("document", "fetch", SRC)(document, fetch);
  await new Promise(r => setTimeout(r, 120));

  const table = dom["dl-live"].children[0] || null;
  const tbody = table ? table.children.find(c => c.tagName === "tbody") : null;
  const rows = tbody ? tbody.children : [];
  return {
    table, rows, fetched,
    fallbackHidden: dom["dl-fallback"].hidden,
    status: dom["dl-status"].textContent,
    caption: table && table.children[0] ? table.children[0].textContent : "",
    hrefs: rows.map(r => r.children[0].children[0]._href),
    names: rows.map(r => r.children[0].children[0].textContent),
    sizes: rows.map(r => r.children[1].textContent),
    hashes: rows.map(r => r.children[2].textContent),
  };
}

function live() {
  return process.env.SITE_TEST_LIVE === "1";
}

// Live mode exists for a human running it by hand (SITE_TEST_LIVE=1), to
// confirm GitHub still sends the fields this test assumes. It reads only the
// API, never the download path — a curl here cannot reproduce a browser's CORS
// rules, so hitting github.com would prove nothing even if it succeeded.
async function loadLive() {
  const r = await fetch(API, { headers: { Accept: "application/vnd.github+json" } });
  if (!r.ok) throw new Error("the API answered " + r.status);
  return r.json();
}

(async function main() {
  console.log("site.test.js — " + (live() ? "live API" : "fixtures") + "\n");

  // --- static discipline -------------------------------------------------
  // The comment in site.js promises API strings are never written as markup.
  // This keeps that promise from being quietly dropped in a later edit. The
  // check runs on code only (comments stripped), because the rationale comment
  // at the top of site.js itself names innerHTML as the mistake to avoid.
  const codeOnly = SRC
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter(l => !/^\s*\/\//.test(l))
    .join("\n");
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML/.test(codeOnly),
    "site.js must not build markup from strings (innerHTML found in code)");
  ok("site.js contains no innerHTML/outerHTML/insertAdjacentHTML (code only)");

  const needed = ["dl-live", "dl-status", "dl-fallback"];
  needed.forEach(id => {
    assert.ok(idsInHTML.has(id), "index.html is missing id=\"" + id + "\"");
  });
  ok("index.html carries every element id site.js looks up", needed.join(", "));

  const release = live() ? await loadLive() : RELEASE;

  // --- A. the real shape -------------------------------------------------
  console.log("\nA. real payload (digests, one request)");
  const a = await run(release);
  const assetNames = (release.assets || []).map(x => x.name);
  eq("every asset in the release gets a row", a.rows.length, assetNames.length);
  eq("fallback list is hidden once the live table renders", a.fallbackHidden, true);
  eq("no href outside the download path", violations.length, 0);
  assert.ok(a.caption.indexOf(release.tag_name) !== -1, "caption must name the tag");
  ok("caption names the release", a.caption);

  // The request budget: exactly one, to the one origin that sends CORS
  // headers. This is the assertion that fails for the bug a browser reported
  // and a DOM stub did not — the old code fetched checksums.txt from
  // github.com/.../releases/download/... and every real user saw no hashes.
  eq("no request to an origin browsers block (CORS)", corsViolations.length, 0);
  eq("exactly one network request", a.fetched.length, 1);
  eq("the one request goes to api.github.com", a.fetched[0], API);

  // The hash column comes from `digest` in that same response: this is the
  // check that would have caught a misnamed field.
  const amd64 = a.names.findIndex(n => /_windows_amd64\.zip$/.test(n));
  if (amd64 >= 0) {
    const expected = String(release.assets.find(
      x => x.name === a.names[amd64]).digest).replace(/^sha256:/, "");
    eq("SHA-256 column matches the asset's own digest for " + a.names[amd64],
      a.hashes[amd64], expected);
    eq("digest arrives with the sha256: prefix stripped", a.hashes[amd64].length, 64);
    eq("size column is the byte count, humanised", a.sizes[amd64], "5.8 MiB");
  } else {
    ok("no amd64 zip in this release, hash-column check skipped");
  }
  // Every asset in this fixture carries a digest, so every cell is a hash and
  // none is the "no hash" marker.
  eq("no asset shows the em dash in the all-digests release",
    a.hashes.filter(h => h === "\u2014").length, 0);
  eq("status states where the digests came from", /one response/.test(a.status), true);

  // --- B. hostile payload ------------------------------------------------
  console.log("\nB. hostile payload");
  const evil = {
    tag_name: "v9.9.9",
    published_at: "2026-01-01T00:00:00Z",
    assets: [
      { name: "<img src=x onerror=alert(1)>", size: null, browser_download_url: PREFIX + "v9.9.9/x" },
      { name: "js", size: 1, browser_download_url: "javascript:alert(1)" },
      { name: "foreign", size: 1, browser_download_url: "https://evil.com/pullgoscript/releases/download/v9/x" },
      { name: "traversal", size: 1, browser_download_url: PREFIX + "v9.9.9/../../../evil" },
    ],
  };
  const b = await run(evil);
  eq("only the one asset on the real download path survives", b.names,
    ["<img src=x onerror=alert(1)>"]);
  eq("no href outside the download path", violations.length, 0);
  eq("still only one request, and still to the API", b.fetched.length, 1);
  ok("javascript: URL dropped", "js not in " + JSON.stringify(b.names));
  ok("foreign host dropped", "foreign not in " + JSON.stringify(b.names));
  ok("traversal dropped after URL resolution", "traversal not in " + JSON.stringify(b.names));

  // --- C. nothing usable -------------------------------------------------
  console.log("\nC. payload where no asset survives the URL check");
  const c = await run({ tag_name: "v0", assets: [{ name: "x", size: 1, browser_download_url: "javascript:1" }] });
  eq("no table is built", c.rows.length, 0);
  eq("the pinned list stays visible", c.fallbackHidden, false);
  assert.ok(/URL check/.test(c.status), "status must name the reason, not just 'could not read'");
  ok("status names the URL check as the reason");

  // --- D. the API refuses ------------------------------------------------
  console.log("\nD. API answers 403 (rate limit)");
  const d = await run(null, { httpStatus: 403 });
  eq("the pinned list stays visible", d.fallbackHidden, false);
  assert.ok(/403/.test(d.status), "status must carry the HTTP status");
  ok("status carries the HTTP status");

  // --- E. digests missing or malformed -----------------------------------
  console.log("\nE. release where digests are absent, truncated or wrong-shaped");
  const thin = {
    tag_name: "v0.0.1",
    published_at: "2026-01-01T00:00:00Z",
    assets: [
      // normal
      { name: "a.zip", size: 10, browser_download_url: PREFIX + "v0.0.1/a.zip",
        digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" },
      // absent
      { name: "b.zip", size: 11, browser_download_url: PREFIX + "v0.0.1/b.zip" },
      // truncated: must not read as a valid hash
      { name: "c.zip", size: 12, browser_download_url: PREFIX + "v0.0.1/c.zip",
        digest: "sha256:1111111" },
      // a different algorithm: not claimed to be sha256
      { name: "d.zip", size: 13, browser_download_url: PREFIX + "v0.0.1/d.zip",
        digest: "sha512:aaaa" },
    ],
  };
  const e = await run(thin);
  eq("all four rows render", e.rows.length, 4);
  eq("the one well-formed digest renders", e.hashes[0],
    "1111111111111111111111111111111111111111111111111111111111111111");
  eq("an absent digest reads as an em dash", e.hashes[1], "\u2014");
  eq("a truncated digest reads as an em dash, not a short hash", e.hashes[2], "\u2014");
  eq("a non-sha256 algorithm reads as an em dash", e.hashes[3], "\u2014");
  assert.ok(/1 of 4/.test(e.status), "status must say how many digests arrived");
  ok("status reports the partial digest count");
  eq("fallback stays hidden: the table is live, just partly hashless", e.fallbackHidden, true);

  // --- F. the static fallback must not drift ------------------------------
  // Only meaningful against the fixture: once a newer release ships, the pinned
  // table in index.html is stale by definition and the fixture is what keeps
  // this check honest.
  if (!live()) {
    console.log("\nF. pinned fallback table in index.html");
    const pinned = [...HTML.matchAll(/<td class="hash">([0-9a-f]{64})<\/td>/g)].map(m => m[1]);
    const fromDigest = RELEASE.assets.map(x => x.digest.replace(/^sha256:/, ""));
    eq("pinned row count", pinned.length, 2);
    pinned.forEach(h => {
      assert.ok(fromDigest.includes(h), "pinned hash not among the release's digests: " + h);
    });
    ok("both pinned hashes match the digests the API reports");
    assert.ok(HTML.indexOf("5.8 MiB") !== -1 && HTML.indexOf("5.4 MiB") !== -1,
      "pinned sizes must match the API byte counts humanised");
    ok("pinned sizes match the API sizes humanised");
  } else {
    console.log("\nF. skipped: pinned table is compared against the fixture, not the live API");
  }

  console.log("\n" + checks + " assertions, all passed");
})().catch(err => {
  console.error("\nFAILED: " + (err && err.message ? err.message : err));
  process.exit(1);
});
