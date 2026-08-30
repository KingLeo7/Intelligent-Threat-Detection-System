// Dashboard: submit a request string for analysis and poll the live counters.
(function () {
  function renderLogs(entries) {
    const list = document.getElementById("logs-list");
    if (!entries.length) {
      list.innerHTML = '<div style="color:#555">No logs yet.</div>';
      return;
    }
    list.innerHTML = entries.slice(0, 5).map(function (entry) {
      return (
        '<div class="log-item">' +
          '<span class="log-url">' + IDPS.escapeHtml(entry.url) + "</span>" +
          '<span class="' + (entry.safe ? "log-safe" : "log-attack") + '">' +
            IDPS.escapeHtml(entry.result) +
            (entry.safe ? "" : " (" + IDPS.escapeHtml(entry.severity) + ")") +
          "</span>" +
          '<span class="meta">[' + IDPS.escapeHtml(entry.type || "full") + "] " +
            (entry.action ? "Action: " + IDPS.escapeHtml(entry.action) : "") +
          "</span>" +
        "</div>"
      );
    }).join("");
  }

  async function loadData() {
    try {
      const res = await IDPS.get("/api/data");
      const data = await res.json();
      document.getElementById("stat-requests").textContent = data.stats.requests;
      document.getElementById("stat-attacks").textContent = data.stats.attacks;
      document.getElementById("stat-blocked").textContent = data.stats.blocked;
      renderLogs(data.logs || []);
    } catch (e) {
      /* transient network error: the next poll will retry */
    }
  }

  function describeFindings(findings) {
    if (!Array.isArray(findings) || !findings.length) return "";
    return findings.map(function (f) {
      return f.category + " [" + f.severity + ", score " + f.score + "/" +
        f.threshold + "] matched: " + f.rules.join(", ") +
        (f.reflected ? " (payload reflected in the response)" : "");
    }).join("\n");
  }

  async function analyze() {
    const input = document.getElementById("url-input");
    const url = input.value.trim();
    if (!url) {
      alert("Enter a request or URL to analyze.");
      return;
    }
    const type = document.querySelector('input[name="check"]:checked').value;
    const box = document.getElementById("result-box");
    box.style.display = "block";
    box.className = "";
    box.textContent = "Analyzing...";

    try {
      const res = await IDPS.post("/api/analyze", { url: url, type: type });
      if (!res.ok) {
        box.className = "danger";
        const body = await res.json().catch(function () { return {}; });
        box.textContent = "Request refused (" + res.status + "): " +
          (body.error || "unknown error");
        return;
      }
      const data = await res.json();
      box.className = data.safe ? "safe" : "danger";
      // textContent, never innerHTML: the value being displayed is the payload.
      box.textContent = data.safe
        ? "Result: Safe"
        : "Result: " + data.result + " detected (" + data.severity + ")";

      const detail = document.createElement("div");
      detail.style.marginTop = "8px";
      detail.style.color = "#ccc";
      detail.style.whiteSpace = "pre-wrap";
      detail.textContent = "Action: " + (data.action || "Blocked request") +
        (data.fetch_note ? "\n" + data.fetch_note : "") +
        (data.safe ? "" : "\n" + describeFindings(data.findings));
      box.appendChild(detail);
      loadData();
    } catch (e) {
      box.className = "danger";
      box.textContent = "Error: cannot reach the server.";
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const button = document.getElementById("analyze-btn");
    if (button) button.addEventListener("click", analyze);
    const input = document.getElementById("url-input");
    if (input) {
      input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") analyze();
      });
    }
    loadData();
    setInterval(loadData, 5000);
  });
})();
