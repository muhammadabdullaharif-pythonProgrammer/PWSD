/* PWDS front-end — AJAX scanner + Chart.js metrics + chatbot */
(function () {
  const csrftoken = () => {
    const m = document.cookie.match(/csrftoken=([^;]+)/);
    return m ? m[1] : "";
  };

  async function postJSON(url, payload) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrftoken(),
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const t = await res.text();
      throw new Error(`HTTP ${res.status}: ${t}`);
    }
    return res.json();
  }

  function verdictBadge(v) {
    const cls = v === "SAFE" ? "success" : v === "SUSPICIOUS" ? "warning" : "danger";
    return `<span class="badge bg-${cls}">${v}</span>`;
  }

  function renderScanResult(r) {
    const recs = (r.recommendations || [])
      .map(x => `<li class="list-group-item d-flex justify-content-between"><span>${x.text}</span><span class="badge bg-secondary">${x.severity}</span></li>`)
      .join("");
    const feats = Object.entries(r.features || {})
      .map(([k, v]) => `<tr><th class="text-capitalize">${k.replace(/_/g, " ")}</th><td>${v}</td></tr>`)
      .join("");
    return `
      <div class="card pwds-card shadow-sm">
        <div class="card-body">
          <div class="d-flex justify-content-between flex-wrap">
            <div><h5 class="mb-1">Scan #${r.id} ${verdictBadge(r.verdict)}</h5>
              <div class="text-muted small">Threat score: <b>${r.threat_score}%</b></div>
              <div class="text-break"><b>URL:</b> ${r.url}</div></div>
            <div>
              <a class="btn btn-outline-primary" href="${r.detail_url}">Open detail</a>
              <a class="btn btn-primary" href="${r.pdf_url}"><i class="bi bi-file-earmark-pdf"></i> PDF</a>
            </div>
          </div>
          <hr>
          <div class="row g-3">
            <div class="col-md-6"><h6>Features</h6><div class="table-responsive"><table class="table table-sm">${feats}</table></div></div>
            <div class="col-md-6"><h6>Recommendations</h6><ul class="list-group">${recs}</ul></div>
          </div>
        </div>
      </div>`;
  }

  async function initDashboard() {
    const form = document.getElementById("scan-form");
    const progress = document.getElementById("scan-progress");
    const result = document.getElementById("scan-result");

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const url = document.getElementById("scan-url").value.trim();
      if (!url) return;
      progress.classList.remove("d-none");
      result.innerHTML = "";
      try {
        const data = await postJSON("/scanner/api/scan/", { url });
        result.innerHTML = renderScanResult(data);
        await loadMetrics();
      } catch (err) {
        result.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
      } finally {
        progress.classList.add("d-none");
      }
    });

    await loadMetrics();
  }

  let chartVerdict, chartDaily;
  async function loadMetrics() {
    const res = await fetch("/scanner/api/metrics/", { credentials: "same-origin" });
    const data = await res.json();
    document.getElementById("m-total").textContent = data.totals.all;
    document.getElementById("m-safe").textContent  = data.totals.safe;
    document.getElementById("m-sus").textContent   = data.totals.suspicious;
    document.getElementById("m-ph").textContent    = data.totals.phishing;

    const vctx = document.getElementById("chart-verdict");
    if (vctx) {
      const cfg = {
        type: "doughnut",
        data: {
          labels: ["Safe", "Suspicious", "Phishing"],
          datasets: [{
            data: [data.totals.safe, data.totals.suspicious, data.totals.phishing],
            backgroundColor: ["#1a7f37", "#b86e00", "#c4302b"],
          }],
        },
        options: { plugins: { legend: { position: "bottom" } } },
      };
      if (chartVerdict) chartVerdict.destroy();
      chartVerdict = new Chart(vctx, cfg);
    }

    const dctx = document.getElementById("chart-daily");
    if (dctx) {
      const labels = Object.keys(data.per_day);
      const values = Object.values(data.per_day);
      const cfg = {
        type: "line",
        data: { labels, datasets: [{
          label: "Scans", data: values, borderColor: "#0b3d91",
          backgroundColor: "rgba(11,61,145,.15)", fill: true, tension: .3,
        }]},
        options: { plugins: { legend: { display: false } } },
      };
      if (chartDaily) chartDaily.destroy();
      chartDaily = new Chart(dctx, cfg);
    }
  }

  function initChatbot() {
    const form = document.getElementById("chat-form");
    const input = document.getElementById("chat-input");
    const win = document.getElementById("chat-window");

    function append(role, text, cls) {
      const div = document.createElement("div");
      div.className = "mb-2 " + (cls || "");
      div.innerHTML = `<b>${role}:</b> ${text}`;
      win.appendChild(div);
      win.scrollTop = win.scrollHeight;
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const msg = input.value.trim();
      if (!msg) return;
      append("You", msg);
      input.value = "";
      try {
        const data = await postJSON("/chatbot/api/ask/", { message: msg });
        append("PWDS", data.answer, "text-primary");
      } catch (err) {
        append("PWDS", `(error: ${err.message})`, "text-danger");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (window.PWDS_BOOT === "dashboard") initDashboard();
    if (window.PWDS_BOOT === "chatbot")   initChatbot();
  });
})();
