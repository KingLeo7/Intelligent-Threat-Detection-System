// Settings page: reset controls plus a read-only view of the active policy.
(function () {
  const summary = document.getElementById("settings-summary");
  const rulesBox = document.getElementById("rules-summary");

  async function loadSummary() {
    try {
      const res = await IDPS.get("/api/data");
      const data = await res.json();
      summary.textContent =
        "Requests: " + data.stats.requests +
        " | Attacks: " + data.stats.attacks +
        " | Blocked IPs: " + data.blocked_ips.length +
        " | Signed in as: " + (data.user || "unknown") +
        (data.is_admin ? " (admin)" : "");
    } catch (e) {
      summary.textContent = "Failed to load system status.";
    }
  }

  async function loadRules() {
    if (!rulesBox) return;
    try {
      const res = await IDPS.get("/api/rules");
      const data = await res.json();
      const byCategory = {};
      data.rules.forEach(function (rule) {
        byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
      });
      rulesBox.innerHTML = Object.keys(byCategory).map(function (category) {
        return (
          '<div class="list-item">' +
            IDPS.escapeHtml(category) + ": " + byCategory[category] +
            " rule(s), reported at score &ge; " +
            IDPS.escapeHtml(data.thresholds[category]) +
          "</div>"
        );
      }).join("");
    } catch (e) {
      rulesBox.textContent = "Failed to load the rule summary.";
    }
  }

  function resetAction(path, question) {
    return async function () {
      if (!confirm(question)) return;
      const res = await IDPS.post(path);
      if (!res.ok) {
        alert("Request refused (" + res.status + ").");
        return;
      }
      loadSummary();
    };
  }

  document.addEventListener("DOMContentLoaded", function () {
    IDPS.bindActions({
      "reset-stats": resetAction("/api/reset-stats", "Reset all statistics?"),
      "clear-logs": resetAction("/api/clear-logs", "Clear all attack logs?"),
      "clear-blocked": resetAction("/api/clear-blocked", "Clear all blocked IPs?"),
    });
    loadSummary();
    loadRules();
  });
})();
