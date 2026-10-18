// Reads the newest release from the GitHub API so the download table never
// goes stale between releases. One request, one origin.
//
// The SHA-256 column comes from the `digest` field that every release asset
// already carries in that same response. It deliberately does NOT fetch
// checksums.txt to parse it: that file sits behind
// github.com/.../releases/download/..., which answers with a 302 to a CDN that
// sends no Access-Control-Allow-Origin — so a browser refuses to read it and
// the console reports "blocked by CORS policy". (Following the redirect from
// the API asset endpoint does not help either: the *final* response is the one
// the browser checks, and it has no ACAO header.) The api.github.com origin
// does send `Access-Control-Allow-Origin: *`, so everything on this page is
// readable in exactly one request, from one origin.
//
// Every string that comes from the API is written with textContent, never
// innerHTML, and every href is resolved and checked against this repo's own
// asset path before it is assigned. The console's v1 had a DOM XSS from
// rendering server data through innerHTML; a docs page fed by an API deserves
// the same discipline.
(function () {
  "use strict";

  var REPO = "DevCop95/pullgoscript";
  var API = "https://api.github.com/repos/" + REPO + "/releases/latest";
  var ORIGIN = "https://github.com";
  var ASSET_PATH = "/" + REPO + "/releases/download/";

  var mount = document.getElementById("dl-live");
  var fallback = document.getElementById("dl-fallback");
  var status = document.getElementById("dl-status");
  if (!mount || !status) return;

  function el(tag, text, cls) {
    var n = document.createElement(tag);
    if (text !== null && text !== undefined) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  }

  // A startsWith check on the raw string is not enough. This URL starts with
  // the asset prefix and still resolves outside the download path:
  //
  //   https://github.com/DevCop95/pullgoscript/releases/download/v9/../../../evil
  //                                          -> https://github.com/DevCop95/evil
  //
  // So resolve the URL and check the origin and the path it actually ends up
  // at. Anything that survives the string check but escapes after resolution
  // is dropped, which fails closed: no row, and the caller falls back.
  function safeURL(u) {
    if (typeof u !== "string" || u.indexOf(ORIGIN + ASSET_PATH) !== 0) return null;
    var parsed;
    try {
      parsed = new URL(u);
    } catch (err) {
      return null;
    }
    if (parsed.origin !== ORIGIN) return null;
    if (parsed.pathname.indexOf(ASSET_PATH) !== 0) return null;
    return parsed.href;
  }

  function human(bytes) {
    if (typeof bytes !== "number") return "";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
  }

  // GitHub reports digests as "sha256:<64 hex>". Anything else — absent, a
  // different algorithm, a truncated value — reads as no hash rather than as
  // a plausible-looking one, so a wrong column never looks right.
  var NO_HASH = "\u2014";
  function hashOf(digest) {
    if (typeof digest !== "string" || digest.indexOf("sha256:") !== 0) return NO_HASH;
    var hex = digest.slice(7);
    return /^[0-9a-f]{64}$/.test(hex) ? hex : NO_HASH;
  }

  function render(release) {
    var assets = (release.assets || []).filter(function (a) {
      return safeURL(a.browser_download_url);
    });
    if (!assets.length) throw new Error("no release asset survived the URL check");

    var withHash = assets.filter(function (a) { return hashOf(a.digest) !== NO_HASH; }).length;

    var table = el("table");
    table.appendChild(el("caption", "Latest release: " + release.tag_name +
      ", published " + String(release.published_at || "").slice(0, 10)));

    var thead = el("thead");
    var htr = el("tr");
    ["File", "Size", "SHA-256"].forEach(function (h) { htr.appendChild(el("th", h)); });
    thead.appendChild(htr);
    table.appendChild(thead);

    var tbody = el("tbody");
    assets.forEach(function (a) {
      var tr = el("tr");

      var td = el("td");
      var link = el("a", a.name);
      link.href = safeURL(a.browser_download_url);
      td.appendChild(link);
      tr.appendChild(td);

      tr.appendChild(el("td", human(a.size)));
      tr.appendChild(el("td", hashOf(a.digest), "hash"));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    while (mount.firstChild) mount.removeChild(mount.firstChild);
    mount.appendChild(table);
    if (fallback) fallback.hidden = true;

    status.textContent = withHash === assets.length
      ? "Read live from the GitHub API — filenames, sizes and SHA-256 digests all come from this one response."
      : "Read live from the GitHub API. " + withHash + " of " + assets.length +
        " assets carry an SHA-256 digest in the release metadata; the rest show an em dash.";
  }

  fetch(API, { headers: { Accept: "application/vnd.github+json" } })
    .then(function (r) {
      if (!r.ok) throw new Error("the API answered " + r.status);
      return r.json();
    })
    .then(render)
    .catch(function (err) {
      status.textContent = "Could not build the live table automatically (" +
        err.message + "). The pinned list below is the v2.0.2 snapshot; the " +
        "Releases page is always current.";
      if (fallback) fallback.hidden = false;
    });
})();
