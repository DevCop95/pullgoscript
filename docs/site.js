// Reads the newest release from the GitHub API so the download table never
// goes stale between releases.
//
// Every string that comes from the API is written with textContent, never
// innerHTML, and every href is checked against this repo's own asset prefix
// before it is assigned. The console's v1 had a DOM XSS from rendering
// server data through innerHTML; a docs page fed by an API deserves the same
// discipline.
(function () {
  "use strict";

  var REPO = "DevCop95/pullgoscript";
  var API = "https://api.github.com/repos/" + REPO + "/releases/latest";
  var PREFIX = "https://github.com/" + REPO + "/releases/download/";

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

  function safeURL(u) {
    return typeof u === "string" && u.indexOf(PREFIX) === 0 ? u : null;
  }

  function human(bytes) {
    if (typeof bytes !== "number") return "";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
  }

  function parseSums(text) {
    var out = {};
    String(text || "").split("\n").forEach(function (line) {
      var m = line.trim().split(/\s+/);
      if (m.length >= 2) out[m[1]] = m[0];
    });
    return out;
  }

  function render(release, sums) {
    var assets = (release.assets || []).filter(function (a) {
      return safeURL(a.browser_download_url);
    });
    if (!assets.length) throw new Error("the latest release has no assets");

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
      tr.appendChild(el("td", sums[a.name] || "\u2014", "hash"));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    while (mount.firstChild) mount.removeChild(mount.firstChild);
    mount.appendChild(table);
    if (fallback) fallback.hidden = true;
    status.textContent = "Read live from the GitHub API, so this table follows " +
      "the newest release without a rebuild.";
  }

  fetch(API, { headers: { Accept: "application/vnd.github+json" } })
    .then(function (r) {
      if (!r.ok) throw new Error("the API answered " + r.status);
      return r.json();
    })
    .then(function (release) {
      var sums = (release.assets || []).filter(function (a) {
        return a.name === "checksums.txt";
      })[0];
      var sumsURL = sums ? safeURL(sums.browser_download_url) : null;
      if (!sumsURL) return render(release, {});
      return fetch(sumsURL)
        .then(function (r) { return r.ok ? r.text() : ""; })
        .then(function (t) { render(release, parseSums(t)); })
        .catch(function () { render(release, {}); });
    })
    .catch(function (err) {
      status.textContent = "Could not read the release list automatically (" +
        err.message + "). The pinned list below is the v2.0.2 snapshot; the " +
        "Releases page is always current.";
      if (fallback) fallback.hidden = false;
    });
})();
