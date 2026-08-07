/**
 * mona.expert — Website Gateway
 * Handles the live security check demo and dashboard connectivity.
 */

document.addEventListener("DOMContentLoaded", () => {
  initSecurityCheck();
  initNavHighlight();
});

// ─── Try-It: Live Security Check ──────────────────────────
function initSecurityCheck() {
  const input = document.getElementById("try-input");
  const btn = document.getElementById("try-btn");
  const result = document.getElementById("try-result");

  if (!input || !btn || !result) return;

  btn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text) return;

    btn.disabled = true;
    btn.textContent = "Checking…";

    try {
      const res = await fetch("/api/security-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: text }),
      });

      const data = await res.json();

      result.classList.remove("hidden", "blocked", "allowed", "review");

      if (data.blocked) {
        result.classList.add("blocked");
        const hits = data.triggeredRules || [];
        const injHits = data.injectionGuard?.analysis?.evidence?.allLabels || [];
        result.innerHTML = `
          <div class="result-header">🛑 BLOCKED — Injection detected</div>
          <div class="result-score">Score: ${data.injectionGuard?.analysis?.totalScore || data.riskScore}</div>
          <div class="result-detail">
            Patterns triggered: ${injHits.join(", ") || hits.map(h => h.label).join(", ")}
            ${data.injectionGuard?.analysis?.matchCount ? `<br>${data.injectionGuard.analysis.matchCount} of 21 patterns matched` : ""}
          </div>
        `;
      } else if (data.requiresReview) {
        result.classList.add("review");
        result.innerHTML = `
          <div class="result-header">⚠️ REVIEW NEEDED</div>
          <div class="result-score">Score: ${data.riskScore}</div>
          <div class="result-detail">Input flagged for manual review. Not automatically blocked.</div>
        `;
      } else {
        result.classList.add("allowed");
        result.innerHTML = `
          <div class="result-header">✅ ALLOWED — No threats detected</div>
          <div class="result-score">Score: ${data.riskScore}</div>
          <div class="result-detail">All 21 injection patterns passed. Safe to proceed.</div>
        `;
      }
    } catch (err) {
      result.classList.remove("hidden");
      result.classList.add("blocked");
      result.innerHTML = `
        <div class="result-header">⚠️ Connection error</div>
        <div class="result-detail">
          Could not reach the security wrapper.
          ${err.message ? `<br>${err.message}` : ""}
          <br><br>Is the wrapper backend running? Try:
          <br><code>npm run start:wrapper</code>
        </div>
      `;
    } finally {
      btn.disabled = false;
      btn.textContent = "Run Security Check";
    }
  });

  // Allow Enter key to trigger check
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.ctrlKey) {
      btn.click();
    }
  });
}

// ─── Nav: Highlight current page ─────────────────────────
function initNavHighlight() {
  const path = window.location.pathname;
  document.querySelectorAll(".nav-links a").forEach((link) => {
    const href = link.getAttribute("href");
    if (href === path || (path === "/" && href === "/")) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });
}

// ─── Live status check (periodic) ────────────────────────
async function checkStatus() {
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    const badge = document.getElementById("nav-status");
    if (badge) {
      if (data.mtls) {
        badge.textContent = "🔒 mTLS Active";
        badge.className = "badge badge-secure";
      } else {
        badge.textContent = "⚠️ mTLS Off";
        badge.className = "badge";
        badge.style.background = "rgba(245,158,11,0.15)";
        badge.style.color = "var(--orange)";
      }
    }
  } catch {
    const badge = document.getElementById("nav-status");
    if (badge) {
      badge.textContent = "🔴 Offline";
      badge.className = "badge";
      badge.style.background = "rgba(239,68,68,0.15)";
      badge.style.color = "var(--red)";
    }
  }
}

// Check status on load and periodically
checkStatus();
setInterval(checkStatus, 30000);
