// Shared front-end helpers. Loaded before every page script.
//
// Two jobs: keep a CSRF token cached for state-changing requests, and give every
// page one escaping function so user-controlled log values are never written
// into innerHTML unescaped.
window.IDPS = (function () {
  let cachedToken = null;

  async function token() {
    if (cachedToken) return cachedToken;
    const res = await fetch("/api/csrf-token", { credentials: "same-origin" });
    if (!res.ok) throw new Error("could not obtain a CSRF token");
    cachedToken = (await res.json()).csrf_token;
    return cachedToken;
  }

  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": await token(),
      },
      body: JSON.stringify(body || {}),
    });
    if (res.status === 403) {
      // Token rotated with the session: drop it and retry once.
      cachedToken = null;
      return fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": await token(),
        },
        body: JSON.stringify(body || {}),
      });
    }
    return res;
  }

  async function get(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    if (res.status === 401) {
      window.location.href = "/";
      throw new Error("session expired");
    }
    return res;
  }

  function escapeHtml(value) {
    return String(value === undefined || value === null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Binds click handlers by data-action attribute, so no page needs an inline
  // onclick= (which the Content-Security-Policy blocks).
  function bindActions(handlers) {
    document.querySelectorAll("[data-action]").forEach(function (el) {
      const handler = handlers[el.getAttribute("data-action")];
      if (handler) el.addEventListener("click", handler);
    });
  }

  function severityClass(severity) {
    return "sev-" + String(severity || "info").toLowerCase();
  }

  return { token, post, get, escapeHtml, bindActions, severityClass };
})();
