// Attack log page.
(function () {
  const list = document.getElementById("logs-list");

  function render(entries) {
    if (!entries.length) {
      list.innerHTML = '<div style="color:#555">No logs available.</div>';
      return;
    }
    list.innerHTML = entries.map(function (entry) {
      const rules = (entry.findings || [])
        .flatMap(function (f) { return f.rules; })
        .slice(0, 6)
        .map(IDPS.escapeHtml)
        .join(", ");
      return (
        '<div class="log-item">' +
          '<span class="log-url">' + IDPS.escapeHtml(entry.url) + "</span>" +
          '<span class="' + (entry.safe ? "log-safe" : "log-attack") + '">' +
            IDPS.escapeHtml(entry.result) +
            (entry.safe ? "" : " (" + IDPS.escapeHtml(entry.severity) + ")") +
          "</span>" +
          '<span class="meta">' +
            IDPS.escapeHtml(entry.timestamp || "") + " &middot; " +
            "[" + IDPS.escapeHtml(entry.type || "full") + "] " +
            (entry.ip ? "from " + IDPS.escapeHtml(entry.ip) + " " : "") +
            (entry.action ? "&middot; " + IDPS.escapeHtml(entry.action) : "") +
            (rules ? "<br>matched: " + rules : "") +
            (entry.fetch_note ? "<br>" + IDPS.escapeHtml(entry.fetch_note) : "") +
          "</span>" +
        "</div>"
      );
    }).join("");
  }

  async function loadLogs() {
    try {
      const res = await IDPS.get("/api/data");
      render((await res.json()).logs || []);
    } catch (e) {
      list.innerHTML = '<div style="color:#f44">Failed to load logs.</div>';
    }
  }

  async function clearLogs() {
    if (!confirm("Clear all attack logs?")) return;
    const res = await IDPS.post("/api/clear-logs");
    if (!res.ok) {
      alert("Could not clear the logs (" + res.status + ").");
      return;
    }
    loadLogs();
  }

  document.addEventListener("DOMContentLoaded", function () {
    IDPS.bindActions({ "clear-logs": clearLogs });
    loadLogs();
    setInterval(loadLogs, 10000);
  });
})();
