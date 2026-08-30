// Admin panel: vulnerability rollup + account management.
(function () {
  const vulnBlock = document.getElementById("vulnerabilities");
  const usersBlock = document.getElementById("users-list");
  const identity = document.getElementById("admin-identity");

  function summaryRow(label, value) {
    return '<div class="summary"><strong>' + label + ":</strong> " +
      IDPS.escapeHtml(value) + "</div>";
  }

  function renderCounts(counts) {
    const keys = Object.keys(counts || {});
    if (!keys.length) return "No vulnerabilities recorded yet.";
    return keys.sort(function (a, b) { return counts[b] - counts[a]; })
      .map(function (key) {
        return "&#9679; " + IDPS.escapeHtml(key) + ": " + counts[key];
      }).join("<br>");
  }

  function renderRecent(entries) {
    if (!Array.isArray(entries) || !entries.length) {
      return '<div class="summary">No recent attack logs.</div>';
    }
    return entries.slice(0, 5).map(function (entry) {
      return (
        '<div class="list-item">' +
          "<strong>" + IDPS.escapeHtml(entry.result || "Unknown") + "</strong> " +
          "(" + IDPS.escapeHtml(entry.severity || "info") + ") &mdash; " +
          IDPS.escapeHtml(entry.ip || "?") + " &mdash; " +
          IDPS.escapeHtml(entry.url || "") +
        "</div>"
      );
    }).join("");
  }

  function renderUsers(data) {
    if (!data || !Array.isArray(data.users) || !data.users.length) {
      return '<div class="summary">No registered users found.</div>';
    }
    return data.users.map(function (user) {
      const history = (data.history && data.history[user.username]) || [];
      const rows = history.length
        ? history.map(function (h) {
            return '<div class="list-item">' +
              IDPS.escapeHtml(h.type || "") + " &mdash; " +
              IDPS.escapeHtml(h.result || "") + " &mdash; " +
              IDPS.escapeHtml(h.url || "") +
            "</div>";
          }).join("")
        : '<div class="summary">No scan history</div>';
      return (
        '<div class="list-item"><strong>' + IDPS.escapeHtml(user.username) +
          "</strong> &mdash; role: " + IDPS.escapeHtml(user.role) +
          (user.created_at ? " &mdash; joined " + IDPS.escapeHtml(user.created_at) : "") +
        "</div>" + rows
      );
    }).join("");
  }

  async function loadAdmin() {
    vulnBlock.textContent = "Loading vulnerability summary...";
    usersBlock.textContent = "Loading user list...";
    try {
      const [vulnRes, usersRes, dataRes] = await Promise.all([
        IDPS.get("/api/admin/vulnerabilities"),
        IDPS.get("/api/admin/users"),
        IDPS.get("/api/data"),
      ]);
      const vuln = await vulnRes.json();
      const users = await usersRes.json();
      const data = await dataRes.json();

      if (identity) {
        identity.textContent = (data.user || "unknown") + (data.is_admin ? " (admin)" : "");
      }
      vulnBlock.innerHTML =
        summaryRow("Total Requests", vuln.stats.requests || 0) +
        summaryRow("Total Attacks", vuln.stats.attacks || 0) +
        summaryRow("Blocked IPs", (vuln.blocked_ips || []).length) +
        '<div class="summary"><strong>Attack types:</strong><br>' +
          renderCounts(vuln.counts) + "</div>" +
        '<div class="summary"><strong>By severity:</strong><br>' +
          renderCounts(vuln.severities) + "</div>" +
        '<div class="summary"><strong>Recent attackers:</strong></div>' +
        renderRecent(vuln.recent_logs);
      usersBlock.innerHTML = renderUsers(users);
    } catch (error) {
      vulnBlock.textContent = "Failed to load admin data.";
      usersBlock.textContent = "Failed to load user list.";
    }
  }

  async function clearUsers() {
    if (!confirm("Remove every non-administrator account?")) return;
    const res = await IDPS.post("/api/admin/users/clear");
    if (!res.ok) {
      alert("Request refused (" + res.status + ").");
      return;
    }
    const body = await res.json();
    alert("Removed " + (body.deleted || 0) + " account(s).");
    loadAdmin();
  }

  document.addEventListener("DOMContentLoaded", function () {
    IDPS.bindActions({ refresh: loadAdmin, "clear-users": clearUsers });
    loadAdmin();
  });
})();
