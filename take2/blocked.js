// Blocked IP page.
(function () {
  const list = document.getElementById("blocked-list");

  async function loadBlocked() {
    try {
      const res = await IDPS.get("/api/data");
      const ips = (await res.json()).blocked_ips || [];
      list.innerHTML = ips.length
        ? ips.map(function (ip) {
            return '<div class="ip-item">' + IDPS.escapeHtml(ip) + "</div>";
          }).join("")
        : '<div style="color:#555">No blocked IPs.</div>';
    } catch (e) {
      list.innerHTML = '<div style="color:#f44">Failed to load blocked IPs.</div>';
    }
  }

  async function clearBlocked() {
    if (!confirm("Clear all blocked IPs?")) return;
    const res = await IDPS.post("/api/clear-blocked");
    if (!res.ok) {
      alert("Could not clear the blocked list (" + res.status + ").");
      return;
    }
    loadBlocked();
  }

  document.addEventListener("DOMContentLoaded", function () {
    IDPS.bindActions({ "clear-blocked": clearBlocked });
    loadBlocked();
    setInterval(loadBlocked, 10000);
  });
})();
