// Runs docs/site.js — the file Pages actually serves — against a minimal DOM
// stub, so what it reads from the GitHub API and the URL check it applies are
// asserted instead of assumed.
//
// Why this exists: site.js renders the download table, and no Go test can see
// it. A renamed field, a broken URL check or an element id changed in
// index.html all fail *quietly* — the reader gets an empty table and no error
// on either side. That is not hypothetical: the first shipped version of the
// URL check accepted
//
//   https://github.com/DevCop95/pullgoscript/releases/download/v9/../../../evil
//
// which resolves to https://github.com/DevCop95/evil. Running the file found
// it; reading it did not. So the file gets run.
//
// No dependencies and no network: `node docs/site.test.js` in CI, nothing to
// install. The fixtures are trimmed copies of a real
// /repos/DevCop95/pullgoscript/releases/latest response (v2.0.2, published
// 2026-10-17) and of that release's checksums.txt, so the shapes are the ones
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
// Sizes are the byte counts the API reported, which is also what pins the
// human-readable column: 6131480 must render as "5.8 MiB", the same string the
// static fallback table in index.html carries by hand.

const CHECKSUMS = [
  "90b2e6e5794ed17892ccded42df81ea74840ca40b50370bd9fc7e117d9cff3c8  obliteratus_2.0.2_windows_amd64.zip",
  "ce40c67281c31eb540e8f4639894bf471b110f1fb35136ed413344dd64477c66  obliteratus_2.0.2_windows_amd64.zip.sbom.json",
  "ae47be1d2bbce867b6e5f08de35be2e3d90649ffa8bf9c7bdecc1930cb077160  obliteratus_2.0.2_windows_arm64.zip",
  "68b9ab079ed67a5b5dba381ec2cff53f3b9dcf6ebe74de1a57a778d442a3662c  obliteratus_2.0.2_windows_arm64.zip.sbom.json",
].join("\n") + "\n";

const RELEASE = {
  tag_name: "v2.0.2",
  published_at: "2026-10-17T13:36:41Z",
  assets: [
    { name: "checksums.txt", size: 428, browser_download_url: PREFIX + "v2.0.2/checksums.txt" },
    { name: "checksums.txt.pem", size: 3268, browser_download_url: PREFIX + "v2.0.2/checksums.txt.pem" },
    { name: "checksums.txt.sig", size: 96, browser_download_url: PREFIX + "v2.0.2/checksums.txt.sig" },
    { name: "obliteratus_2.0.2_windows_amd64.zip", size: 6131480, browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_amd64.zip" },
    { name: "obliteratus_2.0.2_windows_amd64.zip.sbom.json", size: 26548, browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_amd64.zip.sbom.json" },
    { name: "obliteratus_2.0.2_windows_arm64.zip", size: 5622388, browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_arm64.zip" },
    { name: "obliteratus_2.0.2_windows_arm64.zip.sbom.json", size: 26548, browser_download_url: PREFIX + "v2.0.2/obliteratus_2.0.2_windows_arm64.zip.sbom.json" },
  ],
};

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

async function run(payload, opts) {
  opts = opts || {};
  violations = [];
  const dom = { "dl-live": makeEl("div"), "dl-status": makeEl("p"), "dl-fallback": makeEl("table") };
  const fetched = [];

  const document = {
    getElementById: id => (idsInHTML.has(id) ? dom[id] || null : null),
    createElement: makeEl,
  };
  const fetch = url => {
    fetched.push(url);
    if (opts.httpStatus && url.indexOf("/releases/latest") !== -1) {
      return Promise.resolve({ ok: false, status: opts.httpStatus, json: () => Promise.reject(new Error("no body")), text: () => Promise.resolve("") });
    }
    if (url.indexOf("checksums.txt") !== -1) {
      if (opts.sumsBroken) return Promise.reject(new Error("network down"));
      return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(opts.sumsText || "") });
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

async function loadLive(what) {
  const r = await fetch("https://api.github.com/repos/DevCop95/pullgoscript/releases/latest", {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (!r.ok) throw new Error("the API answered " + r.status);
  const release = await r.json();
  if (what === "release") return release;
  const sums = (release.assets || []).find(a => a.name === "checksums.txt");
  if (!sums) return "";
  const t = await fetch(sums.browser_download_url);
  return t.ok ? t.text() : "";
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

  const release = live() ? await loadLive("release") : RELEASE;
  const sumsText = live() ? await loadLive("checksums") : CHECKSUMS;

  // --- A. the real shape -------------------------------------------------
  console.log("\nA. real payload + real checksums.txt");
  const a = await run(release, { sumsText });
  const assetNames = (release.assets || []).map(x => x.name);
  eq("every asset in the release gets a row", a.rows.length, assetNames.length);
  eq("fallback list is hidden once the live table renders", a.fallbackHidden, true);
  eq("no href outside the download path", violations.length, 0);
  assert.ok(a.caption.indexOf(release.tag_name) !== -1, "caption must name the tag");
  ok("caption names the release", a.caption);

  // The hash column is filled from checksums.txt, keyed by asset name: this is
  // the check that would have caught a misnamed field.
  const amd64 = a.names.findIndex(n => /_windows_amd64\.zip$/.test(n));
  if (amd64 >= 0) {
    const published = new Map(
      sumsText.trim().split("\n").map(l => l.trim().split(/\s+/)).filter(p => p.length >= 2)
        .map(p => [p[1], p[0]])
    );
    eq("SHA-256 column matches checksums.txt for " + a.names[amd64],
      a.hashes[amd64], published.get(a.names[amd64]));
    eq("size column is the byte count, humanised", a.sizes[amd64], "5.8 MiB");
  } else {
    ok("no amd64 zip in this release, hash-column check skipped");
  }

  // Assets with no line in checksums.txt must read as "no hash", not as empty
  // (an empty cell looks like a layout bug; an em dash reads as intentional).
  const txt = a.names.findIndex(n => n === "checksums.txt");
  if (txt >= 0) eq("asset absent from checksums.txt shows an em dash", a.hashes[txt], "\u2014");

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
  const b = await run(evil, { sumsText: "" });
  eq("only the one asset on the real download path survives", b.names,
    ["<img src=x onerror=alert(1)>"]);
  eq("no href outside the download path", violations.length, 0);
  ok("javascript: URL dropped", "js not in " + JSON.stringify(b.names));
  ok("foreign host dropped", "foreign not in " + JSON.stringify(b.names));
  ok("traversal dropped after URL resolution", "traversal not in " + JSON.stringify(b.names));

  // --- C. nothing usable -------------------------------------------------
  console.log("\nC. payload where no asset survives the URL check");
  const c = await run({ tag_name: "v0", assets: [{ name: "x", size: 1, browser_download_url: "javascript:1" }] }, { sumsText: "" });
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

  // --- E. checksums.txt unreachable --------------------------------------
  console.log("\nE. release readable, checksums.txt not");
  const e = await run(RELEASE, { sumsBroken: true });
  eq("the table still renders without hashes", e.rows.length, RELEASE.assets.length);
  eq("fallback stays hidden: the table is live, just hashless", e.fallbackHidden, true);

  // --- F. the static fallback must not drift ------------------------------
  // Only meaningful against the fixture: once a newer release ships, the pinned
  // table in index.html is stale by definition and the fixture is what keeps
  // this check honest.
  if (!live()) {
    console.log("\nF. pinned fallback table in index.html");
    const pinned = [...HTML.matchAll(/<td class="hash">([0-9a-f]{64})<\/td>/g)].map(m => m[1]);
    const published = CHECKSUMS.trim().split("\n").map(l => l.split(/\s+/)[0]);
    eq("pinned row count", pinned.length, 2);
    pinned.forEach(h => {
      assert.ok(published.includes(h), "pinned hash not in the published checksums.txt: " + h);
    });
    ok("both pinned hashes match the published checksums.txt");
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
