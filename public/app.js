/* ============================================================
   BreachLens — frontend logic
   ============================================================ */
(function () {
  "use strict";

  const SEVERITY = {
    critical: { color: "#ff4d5e", label: "Critical", rank: 4 },
    high: { color: "#ff8c42", label: "High", rank: 3 },
    medium: { color: "#ffc53d", label: "Medium", rank: 2 },
    low: { color: "#25d0a8", label: "Low", rank: 1 },
    info: { color: "#8a97a8", label: "Info", rank: 0 },
  };

  const RISK_COLORS = {
    Low: "#25d0a8",
    Medium: "#ffc53d",
    High: "#ff8c42",
    Critical: "#ff4d5e",
  };

  // App state (client-side only; chat history lives here, never persisted server-side)
  const state = {
    domain: "",
    scan: null,
    report: null,
    chatHistory: [], // [{role, content}]
    scanning: false,
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // ---------- View switching ----------
  function showView(name) {
    $$(".view").forEach((v) => v.classList.remove("active"));
    const el = document.getElementById("view-" + name);
    if (el) el.classList.add("active");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  // ---------- Animated background (drifting network nodes) ----------
  function initBackground() {
    const canvas = $("#bg-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let w, h, nodes;
    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function resize() {
      w = canvas.width = window.innerWidth * devicePixelRatio;
      h = canvas.height = window.innerHeight * devicePixelRatio;
      canvas.style.width = window.innerWidth + "px";
      canvas.style.height = window.innerHeight + "px";
      const count = Math.min(70, Math.floor((window.innerWidth * window.innerHeight) / 22000));
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.18 * devicePixelRatio,
        vy: (Math.random() - 0.5) * 0.18 * devicePixelRatio,
      }));
    }
    resize();
    window.addEventListener("resize", resize);

    const MAX_DIST = 150 * devicePixelRatio;

    function draw() {
      ctx.clearRect(0, 0, w, h);

      // faint grid
      ctx.strokeStyle = "rgba(255,255,255,0.02)";
      ctx.lineWidth = 1;
      const grid = 60 * devicePixelRatio;
      for (let x = 0; x < w; x += grid) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let y = 0; y < h; y += grid) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // nodes + links
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;
      }
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist < MAX_DIST) {
            const alpha = (1 - dist / MAX_DIST) * 0.16;
            ctx.strokeStyle = `rgba(0,217,255,${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      for (const n of nodes) {
        ctx.fillStyle = "rgba(0,217,255,0.5)";
        ctx.beginPath();
        ctx.arc(n.x, n.y, 1.4 * devicePixelRatio, 0, Math.PI * 2);
        ctx.fill();
      }

      if (!prefersReduced) requestAnimationFrame(draw);
    }
    draw();
    if (prefersReduced) draw(); // single frame
  }

  // ---------- Checklist control ----------
  const checkItem = (step) => document.querySelector(`.check-item[data-step="${step}"]`);

  function resetChecklist() {
    $$(".check-item").forEach((el) => {
      el.classList.remove("active", "done");
      const meta = el.querySelector(".check-meta");
      if (meta) meta.textContent = "";
    });
    checkItem("dns")?.classList.add("active");
    checkItem("ssl")?.classList.add("active");
    checkItem("subdomains")?.classList.add("active");
    checkItem("headers")?.classList.add("active");
    checkItem("files")?.classList.add("active");
  }

  function markDone(step, meta) {
    const el = checkItem(step);
    if (!el) return;
    el.classList.remove("active");
    el.classList.add("done");
    if (meta != null) {
      const m = el.querySelector(".check-meta");
      if (m) m.textContent = meta;
    }
  }

  function activate(step) {
    checkItem(step)?.classList.add("active");
  }

  // ---------- Run a scan (reads NDJSON stream for real progress) ----------
  async function runScan(domain) {
    if (state.scanning) return;
    state.scanning = true;
    state.domain = domain;
    state.chatHistory = [];

    $("#loading-domain-name").textContent = domain;
    resetChecklist();
    showView("loading");

    let resultPayload = null;
    let errorMessage = null;

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain }),
      });

      if (!res.ok && res.headers.get("content-type")?.includes("application/json")) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || "Scan request failed.");
      }
      if (!res.body) {
        // No streaming support — try to parse a single JSON body
        const text = await res.text();
        handleLines(text, (p) => (resultPayload = p), (m) => (errorMessage = m));
      } else {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let nl;
          while ((nl = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, nl).trim();
            buffer = buffer.slice(nl + 1);
            if (line) {
              processEvent(line, (p) => (resultPayload = p), (m) => (errorMessage = m));
            }
          }
        }
        if (buffer.trim()) {
          processEvent(buffer.trim(), (p) => (resultPayload = p), (m) => (errorMessage = m));
        }
      }
    } catch (e) {
      errorMessage = e.message || "We couldn't complete the scan. Please try again.";
    }

    state.scanning = false;

    if (resultPayload) {
      state.scan = resultPayload.scan;
      state.report = resultPayload.report;
      renderResults();
    } else {
      showError(errorMessage || "We couldn't complete the scan. Please try again.");
    }
  }

  function handleLines(text, onResult, onError) {
    text.split("\n").forEach((line) => {
      const t = line.trim();
      if (t) processEvent(t, onResult, onError);
    });
  }

  function processEvent(line, onResult, onError) {
    let evt;
    try {
      evt = JSON.parse(line);
    } catch (_) {
      return;
    }
    if (evt.type === "progress") {
      handleProgress(evt);
    } else if (evt.type === "result") {
      // tick everything done in case any progress lines were buffered
      ["dns", "ssl", "subdomains", "headers", "files", "pass1", "pass2", "pass3"].forEach((s) => markDone(s));
      onResult({ scan: evt.scan, report: evt.report });
    } else if (evt.type === "error") {
      onError(evt.message);
    }
  }

  function handleProgress(evt) {
    const { step, status } = evt;
    if (step === "dns" && status === "done") markDone("dns");
    else if (step === "ssl" && status === "done") markDone("ssl");
    else if (step === "subdomains" && status === "done")
      markDone("subdomains", evt.count != null ? `${evt.count} found` : "");
    else if (step === "headers" && status === "done") markDone("headers");
    else if (step === "files" && status === "done") markDone("files");
    else if (step === "pass1") {
      if (status === "start") {
        activate("pass1");
        const m = checkItem("pass1")?.querySelector(".check-meta");
        if (m && evt.total != null) m.textContent = evt.total === 0 ? "no issues" : `0 / ${evt.total}`;
      } else if (status === "tick") {
        const m = checkItem("pass1")?.querySelector(".check-meta");
        if (m && evt.total != null) m.textContent = `${evt.done} / ${evt.total}`;
      } else if (status === "done") {
        markDone("pass1");
      }
    } else if (step === "pass2") {
      if (status === "start") activate("pass2");
      else if (status === "done") markDone("pass2");
    } else if (step === "pass3") {
      if (status === "start") activate("pass3");
      else if (status === "done") markDone("pass3");
    }
  }

  // ---------- Render results ----------
  function renderResults() {
    const { scan, report } = state;

    $("#result-domain").textContent = report.domain || scan.domain;
    const provider = report.provider || scan.provider;
    $("#result-provider").textContent = provider
      ? `Provider: ${provider}`
      : "Provider: not identified";

    // Gauge
    const score = Math.max(0, Math.min(100, Number(report.overallRiskScore) || 0));
    const level = report.riskLevel || "Low";
    const riskColor = RISK_COLORS[level] || "#25d0a8";
    const arc = $("#gauge-arc");
    const CIRC = 540; // 2πr ≈ 2*π*86
    // Lower score = less arc filled (less risk). Fill proportional to score.
    arc.style.stroke = riskColor;
    const badge = $("#risk-level-badge");
    badge.textContent = level;
    badge.style.color = riskColor;

    // animate score number
    animateNumber($("#gauge-score"), 0, score, 1300);
    requestAnimationFrame(() => {
      arc.style.strokeDashoffset = String(CIRC - (CIRC * score) / 100);
    });

    // Summary + top priority
    $("#summary-text").textContent = report.summary || "";
    $("#top-priority-text").textContent = report.topPriority || "";
    const tpWrap = $("#top-priority-wrap");
    tpWrap.style.display = report.topPriority ? "" : "none";

    // "If left unaddressed" trajectory callout
    const unWrap = $("#unaddressed-wrap");
    if (report.ifUnaddressed && report.ifUnaddressed.trim()) {
      $("#unaddressed-text").textContent = report.ifUnaddressed.trim();
      unWrap.hidden = false;
    } else {
      unWrap.hidden = true;
    }

    // "How this could be exploited" attacker narrative
    const attackSection = $("#attack-section");
    if (report.attackScenario && report.attackScenario.trim()) {
      $("#attack-text").textContent = report.attackScenario.trim();
      attackSection.hidden = false;
    } else {
      attackSection.hidden = true;
    }

    // Certificate history timeline
    renderCertHistory(scan.certificates || []);

    const fbNote = $("#fallback-note");
    fbNote.hidden = report._source !== "fallback" && report._source !== "error";

    // Severity legend
    renderLegend(report.findings || []);

    // Findings
    renderFindings(report.findings || []);

    // Raw signals
    renderRawSignals(scan);

    // Chat reset
    state.chatHistory = [];
    renderChatEmpty();

    showView("results");
    staggerReveal();
  }

  function renderLegend(findings) {
    const counts = {};
    findings.forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
    const legend = $("#severity-legend");
    legend.innerHTML = "";
    ["critical", "high", "medium", "low", "info"].forEach((sev) => {
      if (!counts[sev]) return;
      const item = document.createElement("span");
      item.className = "legend-item";
      item.innerHTML = `<span class="legend-swatch" style="background:${SEVERITY[sev].color}"></span>${counts[sev]} ${SEVERITY[sev].label}`;
      legend.appendChild(item);
    });
    if (!findings.length) {
      legend.innerHTML = `<span class="legend-item"><span class="legend-swatch" style="background:${SEVERITY.low.color}"></span>No issues found</span>`;
    }
  }

  function renderFindings(findings) {
    const list = $("#findings-list");
    list.innerHTML = "";

    if (!findings.length) {
      const empty = document.createElement("div");
      empty.className = "finding reveal";
      empty.style.setProperty("--sev-color", SEVERITY.low.color);
      empty.innerHTML = `
        <div class="finding-summary" style="cursor:default">
          <span class="sev-badge" style="background:${SEVERITY.low.color}">CLEAR</span>
          <span class="finding-title">No notable public exposures detected</span>
        </div>`;
      list.appendChild(empty);
      return;
    }

    findings.forEach((f, i) => {
      const sev = SEVERITY[f.severity] || SEVERITY.low;
      const isInfo = f.informational || f.severity === "info";
      const details = document.createElement("details");
      details.className = "finding reveal" + (isInfo ? " finding-info" : "");
      details.style.setProperty("--sev-color", sev.color);
      details.open = true; // expanded by default — no clicking required to read findings

      const hasRec = f.recommendation && f.recommendation.trim();
      const hasSnippet = f.fixSnippet && String(f.fixSnippet).trim();
      const detailLabel = isInfo ? "Details" : "Why it matters";

      details.innerHTML = `
        <summary class="finding-summary">
          <span class="sev-badge" style="background:${sev.color}">${sev.label}</span>
          <span class="finding-title"></span>
          <svg class="finding-chevron" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>
        </summary>
        <div class="finding-body">
          <div>
            <div class="finding-block-label">${detailLabel}</div>
            <div class="finding-explanation"></div>
          </div>
          ${
            hasRec
              ? `<div>
                   <div class="finding-block-label">Recommended fix</div>
                   <div class="finding-recommendation"></div>
                 </div>`
              : ""
          }
          ${
            hasSnippet
              ? `<div>
                   <div class="finding-block-label">Copy-paste this</div>
                   <div class="snippet-row">
                     <code class="snippet-code"></code>
                     <button type="button" class="snippet-copy">Copy</button>
                   </div>
                 </div>`
              : ""
          }
        </div>`;
      details.querySelector(".finding-title").textContent = f.title || "Finding";
      details.querySelector(".finding-explanation").textContent = f.explanation || "";
      if (hasRec) {
        details.querySelector(".finding-recommendation").textContent = f.recommendation;
      }
      if (hasSnippet) {
        const snippet = String(f.fixSnippet).trim();
        details.querySelector(".snippet-code").textContent = snippet;
        const btn = details.querySelector(".snippet-copy");
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          copySnippet(btn, snippet);
        });
      }
      list.appendChild(details);
    });
  }

  function yn(val) {
    return val
      ? `<span class="pill yes">present</span>`
      : `<span class="pill no">missing</span>`;
  }

  function escapeHtml(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmtDate(s) {
    const t = Date.parse(s);
    if (!Number.isFinite(t)) return "—";
    return new Date(t).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }

  // Certificate history timeline from crt.sh data (descriptive only).
  function renderCertHistory(certs) {
    const section = $("#cert-history");
    const list = $("#cert-timeline");
    if (!certs || !certs.length) {
      section.hidden = true;
      return;
    }
    section.hidden = false;
    list.innerHTML = "";

    const DAY = 86400000;
    let coverageEnd = -Infinity; // latest expiry seen among earlier certs

    certs.forEach((c, i) => {
      const issue = Date.parse(c.notBefore);
      // Flag a coverage gap (possible lapse/downtime) before this cert.
      if (i > 0 && Number.isFinite(issue) && Number.isFinite(coverageEnd)) {
        const gapDays = Math.round((issue - coverageEnd) / DAY);
        if (gapDays > 7) {
          const gapLi = document.createElement("li");
          gapLi.className = "cert-gap";
          gapLi.innerHTML = `<span class="cert-gap-dot"></span><span class="cert-gap-text">~${gapDays}-day gap — possible downtime or certificate lapse</span>`;
          list.appendChild(gapLi);
        }
      }
      const exp = Date.parse(c.notAfter);
      if (Number.isFinite(exp)) coverageEnd = Math.max(coverageEnd, exp);

      const expired = Number.isFinite(exp) && exp < Date.now();
      const statusClass = expired ? "expired" : "active";
      const statusLabel = expired ? "expired" : "active";
      const li = document.createElement("li");
      li.className = "cert-item";
      li.innerHTML = `
        <span class="cert-node${expired ? " expired" : ""}"></span>
        <div class="cert-body">
          <div class="cert-range mono">${fmtDate(c.notBefore)} <span class="cert-arrow">→</span> ${fmtDate(c.notAfter)} <span class="cert-flag ${statusClass}">${statusLabel}</span></div>
          <div class="cert-issuer">${escapeHtml(c.issuer || "Unknown CA")}</div>
        </div>`;
      list.appendChild(li);
    });
  }

  // Clipboard copy with transient "Copied" confirmation on the button.
  async function copySnippet(btn, text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      // Fallback for non-secure contexts
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta);
    }
    const original = btn.dataset.label || btn.textContent;
    btn.dataset.label = original;
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("copied");
    }, 1500);
  }

  function renderRawSignals(scan) {
    const grid = $("#raw-grid");
    const items = [];
    const clean = (text) => `<span class="clean-note">${text}</span>`;

    items.push(["SPF record", yn(scan.dns.spf)]);
    items.push(["DMARC record", yn(scan.dns.dmarc)]);
    // CAA: distinguish present / missing / unknown
    const caa = scan.dns.caa || { status: "unknown" };
    items.push([
      "CAA record",
      caa.status === "present"
        ? `<span class="pill yes">present</span>`
        : caa.status === "missing"
        ? clean("No CAA record set (any CA may issue certs)")
        : clean("Could not be determined by the resolver"),
    ]);
    items.push([
      "MX records",
      scan.dns.mx?.length
        ? `<span class="mono">${scan.dns.mx.map((m) => m.exchange).slice(0, 3).join("<br>")}</span>`
        : clean("No mail (MX) records published"),
    ]);
    if (scan.ssl.expiresInDays != null && !scan.ssl.error) {
      items.push([
        "TLS certificate",
        `<span class="mono">${scan.ssl.expiresInDays} days left</span><br><span style="color:var(--text-faint)">${escapeHtml(scan.ssl.issuer || "")}</span>`,
      ]);
    } else {
      items.push(["TLS certificate", `<span class="pill no">${escapeHtml(scan.ssl.error || "unavailable")}</span>`]);
    }
    items.push(["HSTS header", yn(scan.headers.hsts)]);
    items.push(["Content-Security-Policy", yn(scan.headers.csp)]);
    items.push(["X-Frame-Options", yn(scan.headers.xfo)]);
    items.push(["X-Content-Type-Options", yn(scan.headers.xcto)]);

    // Cookies
    if (scan.cookies) {
      const c = scan.cookies;
      const cookieVal = c.total
        ? `<span class="mono">${c.total} set</span>` +
          (c.missingSecure.length ? `<br><span class="pill no">${c.missingSecure.length} no Secure</span>` : "") +
          (c.missingHttpOnly.length ? ` <span class="pill no">${c.missingHttpOnly.length} no HttpOnly</span>` : "") +
          (c.missingSameSite.length ? ` <span class="pill no">${c.missingSameSite.length} no SameSite</span>` : "")
        : clean("No cookies set on the homepage");
      items.push(["Cookies", cookieVal]);
    }

    // Mixed content
    if (scan.mixedContent) {
      items.push([
        "Mixed content",
        !scan.mixedContent.applicable
          ? clean("Not applicable — site is not served over HTTPS")
          : scan.mixedContent.count
          ? `<span class="pill no">${scan.mixedContent.count} insecure refs</span>`
          : clean("None — page loads all resources over HTTPS"),
      ]);
    }

    // robots.txt / sitemap.xml
    if (scan.robots) {
      items.push([
        "robots.txt",
        scan.robots.present
          ? scan.robots.sensitiveDisallows.length
            ? `<span class="pill no">${scan.robots.sensitiveDisallows.length} sensitive paths</span>`
            : `<span class="pill yes">present, nothing sensitive</span>`
          : clean("No robots.txt found at this domain"),
      ]);
      items.push([
        "sitemap.xml",
        scan.robots.sitemapPresent
          ? `<span class="mono">${scan.robots.sitemapUrlCount != null ? scan.robots.sitemapUrlCount + " urls" : "present"}</span>`
          : clean("No sitemap.xml found at this domain"),
      ]);
    }

    // Exposed sensitive files
    if (scan.exposedFiles) {
      const exposed = scan.exposedFiles.filter((f) => f.exposed);
      const probed = scan.exposedFiles.length;
      items.push([
        "Exposed files",
        exposed.length
          ? `<span class="pill no">${exposed.map((f) => escapeHtml(f.path)).join(", ")}</span>`
          : clean(`None exposed (${probed} sensitive path${probed === 1 ? "" : "s"} probed)`),
      ]);
    }

    items.push([
      "Subdomains",
      scan.subdomainError
        ? `<span class="pill unknown">source unavailable: ${escapeHtml(scan.subdomainError)}</span>`
        : scan.subdomains.length
        ? `<span class="mono">${scan.subdomains.length} found</span>`
        : clean("No subdomains found via certificate transparency logs"),
    ]);

    // Tech stack
    if (scan.tech) {
      const detected = scan.tech.detected || [];
      const techVal = detected.length
        ? `<span class="mono">${detected.map((d) => escapeHtml(d)).join(", ")}</span>` +
          (scan.tech.server ? `<br><span style="color:var(--text-faint)">server: ${escapeHtml(scan.tech.server)}</span>` : "")
        : clean("No common stack signatures detected") +
          (scan.tech.server ? `<br><span style="color:var(--text-faint)">server: ${escapeHtml(scan.tech.server)}</span>` : "");
      items.push(["Tech stack", techVal]);
    }

    items.push([
      "Provider",
      scan.provider
        ? `<span class="mono">${escapeHtml(scan.provider)}</span>`
        : clean("Not identified from nameserver patterns"),
    ]);

    items.push([
      "Nameservers",
      scan.nameservers?.length
        ? `<span class="mono" style="font-size:0.78rem">${scan.nameservers.slice(0, 3).map((n) => escapeHtml(n)).join("<br>")}</span>`
        : clean("No nameservers returned"),
    ]);

    grid.innerHTML = items
      .map(
        ([label, value]) =>
          `<div class="raw-item"><div class="raw-item-label">${label}</div><div class="raw-item-value">${value}</div></div>`
      )
      .join("");
  }

  // ---------- Reveal stagger ----------
  function staggerReveal() {
    const els = $$("#view-results .reveal");
    els.forEach((el, i) => {
      el.classList.remove("in");
      // force reflow so re-renders re-animate
      void el.offsetWidth;
      setTimeout(() => el.classList.add("in"), 80 * i);
    });
  }

  function animateNumber(el, from, to, dur) {
    const start = performance.now();
    function tick(now) {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // ---------- Chat ----------
  function renderChatEmpty() {
    const log = $("#chat-log");
    log.innerHTML = `<div class="chat-empty">Ask anything about these findings — e.g. “Which issue should I fix first?” or “Explain the DMARC finding in simple terms.”</div>`;
  }

  function appendMessage(role, content) {
    const log = $("#chat-log");
    const empty = log.querySelector(".chat-empty");
    if (empty) empty.remove();
    const div = document.createElement("div");
    div.className = "msg " + (role === "user" ? "user" : "bot");
    div.textContent = content;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    return div;
  }

  function appendThinking() {
    const log = $("#chat-log");
    const div = document.createElement("div");
    div.className = "msg bot thinking";
    div.innerHTML = `<span class="dots"><span>●</span><span>●</span><span>●</span></span>`;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    return div;
  }

  async function sendChat(message) {
    appendMessage("user", message);
    state.chatHistory.push({ role: "user", content: message });
    const input = $("#chat-input");
    const sendBtn = $("#chat-send");
    input.value = "";
    input.disabled = true;
    sendBtn.disabled = true;

    const thinking = appendThinking();

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          message,
          report: state.report,
          scan: state.scan,
          history: state.chatHistory.slice(0, -1), // prior turns, excluding this one
        }),
      });
      const data = await res.json().catch(() => ({}));
      const reply = data.reply || "Sorry, I couldn't generate a response. Please try again.";
      thinking.remove();
      appendMessage("bot", reply);
      state.chatHistory.push({ role: "assistant", content: reply });
    } catch (e) {
      thinking.remove();
      appendMessage("bot", "I'm having trouble responding right now. Please try again in a moment.");
    } finally {
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
    }
  }

  // ---------- Error ----------
  function showError(message) {
    $("#error-message").textContent = message;
    showView("error");
  }

  // ---------- Validation ----------
  function normalizeInput(v) {
    return (v || "")
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/^www\./, "")
      .split("/")[0]
      .split("?")[0]
      .split(":")[0]
      .trim();
  }
  const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

  // ---------- Wire up ----------
  function init() {
    initBackground();
    renderChatEmpty();

    $("#scan-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const errEl = $("#form-error");
      errEl.textContent = "";
      const domain = normalizeInput($("#domain-input").value);
      if (!domain || !DOMAIN_RE.test(domain)) {
        errEl.textContent = "Please enter a valid domain like example.com (no http:// or paths).";
        return;
      }
      runScan(domain);
    });

    $$(".sample-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        const d = chip.getAttribute("data-domain");
        $("#domain-input").value = d;
        runScan(d);
      });
    });

    $("#rescan-btn").addEventListener("click", () => {
      if (state.domain) runScan(state.domain);
    });

    $("#download-btn").addEventListener("click", () => window.print());

    $("#error-retry").addEventListener("click", () => {
      $("#domain-input").value = "";
      showView("landing");
    });

    const goHome = () => {
      if (!state.scanning) showView("landing");
    };
    $("#brand-home").addEventListener("click", goHome);
    $("#brand-home").addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") goHome();
    });

    $("#chat-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const msg = $("#chat-input").value.trim();
      if (msg && !$("#chat-input").disabled) sendChat(msg);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
