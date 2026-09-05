/**
 * SOC Cyber Range & Detection-as-Code (DaC) Command Center Client
 * Author: Nayan Solanki
 */

let STATE = {
  techniques: [],
  rules: [],
  currentRule: null,
  telemetryEvents: [],
  queries: {},
  docs: [],
  currentDoc: null,
  dacResults: null,
  isSimulating: false,
  logInterval: null,
  currentTourStep: 0,
  tourSteps: [
    {
      tab: "overview",
      targetId: "header-brand-section",
      targetName: "Cyber Range Subnet",
      title: "1. Cyber Range & Host-Only Subnet",
      desc: "This platform is an enterprise-grade virtualized Cyber Range implementing Detection-as-Code (DaC). It runs within an isolated Host-Only subnet (192.168.56.0/24) to emulate adversaries and validate detections safely.",
      highlights: [
        "Subnet: 192.168.56.0/24 (Virtual Switch)",
        "End-to-end telemetry pipeline: Kali ➔ Windows ➔ SIEM",
        "Standards: MITRE ATT&CK v14 & Sigma Rule Standard"
      ]
    },
    {
      tab: "overview",
      targetId: "header-quick-actions",
      targetName: "Global Action Toolbar",
      title: "2. Global Quick Action Toolbar",
      desc: "Use these top action buttons to control the cyber range from any screen: execute full multi-stage adversary simulations, trigger automated CI/CD DaC test runs, or export structured JSON audit reports.",
      highlights: [
        "⚡ Launch Full Attack: Executes complete 5-technique MITRE kill chain",
        "🧪 Run DaC CI/CD Tests: Validates rules against synthetic telemetry",
        "📄 Export Audit: Downloads timestamped compliance JSON report"
      ]
    },
    {
      tab: "overview",
      targetId: "overview-metrics-grid",
      targetName: "Executive Metrics",
      title: "3. Live Operational Metric Counters",
      desc: "Instant visibility into our SOC posture: 5 fully emulated offensive techniques, 8 vendor-agnostic Sigma detection rules, 100% CI/CD automated validation pass rate, and 3 active subnet nodes.",
      highlights: [
        "Continuous test validation: 0 False Positives",
        "Multi-SIEM Ready: Splunk SPL & Elasticsearch KQL",
        "All offensive and defensive services active"
      ]
    },
    {
      tab: "overview",
      targetId: "overview-nodes-grid",
      targetName: "Cyber Range Nodes",
      title: "4. Infrastructure Node Status",
      desc: "Visual cards representing each isolated virtual host in the cyber range: the Kali Linux adversary node, Windows Server defensive target, and Ubuntu SIEM analytics core.",
      highlights: [
        "Attacker Node: 192.168.56.20 (Python Simulation Engine)",
        "Target Node: 192.168.56.10 (Sysmon 4.90 + Winlogbeat 8.x)",
        "SIEM Node: 192.168.56.30 (Elasticsearch + Kibana + Splunk)"
      ]
    },
    {
      tab: "adversary",
      targetId: "adversary-top-controls",
      targetName: "Attack Parameter Controls",
      title: "5. Safe Adversary Controls & Target IP",
      desc: "Before launching attacks, configure execution parameters: toggle Dry-Run Safe Mode to preview commands without changing host state, or set the defensive Target IP.",
      highlights: [
        "Dry-Run Safe Mode: Non-destructive testing & telemetry verification",
        "Target IP Address input (Default: 192.168.56.10)",
        "Jitter and throttled delay parameters to emulate stealthy APTs"
      ]
    },
    {
      tab: "adversary",
      targetId: "techniques-cards-container",
      targetName: "MITRE Emulation Modules",
      title: "6. MITRE ATT&CK Emulation Modules",
      desc: "Each card represents a modular adversary simulation mapped directly to MITRE ATT&CK techniques. Click 'Execute' on any card to run that specific vector against the defensive node.",
      highlights: [
        "T1110.003: Password Spraying & Brute Force (Event 4625)",
        "T1059.001: Obfuscated PowerShell Execution (Event 4104 & Sysmon 1)",
        "T1003.001: LSASS Memory Dumping & Handle Access (Sysmon 10)",
        "T1547.001: Registry Run Keys & Task Persistence (Sysmon 12/13)",
        "T1070.001: Indicator Removal & Log Clearing (Event 1102/104)"
      ]
    },
    {
      tab: "adversary",
      targetId: "adversary-terminal-card",
      targetName: "Live Terminal Stream",
      title: "7. Real-Time Emulation Terminal Stream",
      desc: "Watch ground-truth attack execution telemetry stream in real time with color-coded log levels, execution timestamps, duration benchmarks, and automated rollback cleanups.",
      highlights: [
        "Real-time polling log streamer from Python simulation engine",
        "Tracks return codes, error handlers, and duration in milliseconds",
        "Clear Terminal button for interactive debugging"
      ]
    },
    {
      tab: "detection",
      targetId: "dac-test-banner",
      targetName: "DaC Automated CI/CD",
      title: "8. Detection-as-Code (DaC) Automated Test Suite",
      desc: "Detection-as-Code treats security rules like production software. Click 'Execute DaC Test Suite' to dynamically evaluate all Sigma rules against synthetic attack telemetry fixtures.",
      highlights: [
        "Automated regression testing for SOC detection rules",
        "Validates True Positives & asserts 0 False Positives",
        "Fast execution benchmarks under 50ms"
      ]
    },
    {
      tab: "detection",
      targetId: "rules-studio-panel",
      targetName: "Sigma Rule Studio & Query Translators",
      title: "9. Interactive Sigma Studio & Multi-SIEM Translator",
      desc: "Inspect, edit, and save vendor-agnostic Sigma YAML detection rules. The engine automatically translates them into production Splunk SPL and Elasticsearch KQL queries with 1-click copy.",
      highlights: [
        "Full YAML editor with mandatory Sigma field validation",
        "Splunk SPL query generator & 1-click copy",
        "Elasticsearch KQL query generator & 1-click copy"
      ]
    },
    {
      tab: "telemetry",
      targetId: "telemetry-table-container",
      targetName: "SIEM Telemetry Logs",
      title: "10. SIEM Telemetry & Raw JSON Inspector",
      desc: "Explore low-level Windows Security & Sysmon 4.90 events shipped into the SIEM. Filter by Event ID, process image, or user, and click 'View JSON' for detailed forensic analysis.",
      highlights: [
        "Windows Security Event IDs: 4625, 4104, 1102, 4698",
        "Sysmon 4.90 Event IDs: 1 (Process), 10 (LSASS), 12/13 (Registry)",
        "Correlated rule badges highlight triggered detection rules"
      ]
    },
    {
      tab: "matrix",
      targetId: "mitre-matrix-grid",
      targetName: "MITRE ATT&CK Matrix",
      title: "11. Interactive ATT&CK Heatmap Grid",
      desc: "Interactive heatmap aligned with MITRE ATT&CK v14. Each tactic column highlights our covered techniques with 100% score badges, linked detection rules, and 1-click execution shortcuts.",
      highlights: [
        "Enterprise tactics: Initial Access, Execution, Persistence, Defense Evasion, Credential Access",
        "Click any technique to jump directly to its simulation card"
      ]
    },
    {
      tab: "docs",
      targetId: "docs-viewer-container",
      targetName: "SOC Documentation Library",
      title: "12. SOC Playbooks & Technical Guides",
      desc: "Access our comprehensive engineering documentation: STRIDE Threat Models, NIST SP 800-61r2 Incident Response Runbooks, Detection Engineering SOPs, and Cloud Cyber Range guides.",
      highlights: [
        "9 detailed technical markdown guides with syntax highlighting",
        "Triage, containment, and eradication workflows",
        "Click 'Finish Tour' to explore the Cyber Range freely!"
      ]
    }
  ]
};

// Initialize app on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  
  loadInitialData();
  startLogStream();

  // Show tour on first visit if not seen
  if (!localStorage.getItem("soc_range_tour_seen")) {
    setTimeout(() => {
      startTour();
    }, 600);
  }

  // Handle window resizing to keep spotlight attached
  window.addEventListener("resize", () => {
    const overlay = document.getElementById("tour-spotlight-overlay");
    if (overlay && !overlay.classList.contains("hidden")) {
      positionSpotlightAndPopover();
    }
  });
});

function switchTab(tabId) {
  // Update tab buttons
  document.querySelectorAll(".tab-btn").forEach(btn => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active", "text-cyan-400", "bg-cyan-950/40", "border-cyan-800/50");
      btn.classList.remove("text-slate-400", "hover:text-slate-200", "hover:bg-slate-800/50");
    } else {
      btn.classList.remove("active", "text-cyan-400", "bg-cyan-950/40", "border-cyan-800/50");
      btn.classList.add("text-slate-400", "hover:text-slate-200", "hover:bg-slate-800/50");
    }
  });

  // Update tab contents
  document.querySelectorAll(".tab-content").forEach(el => {
    if (el.id === `tab-${tabId}`) {
      el.classList.remove("hidden");
      el.classList.add("block");
    } else {
      el.classList.add("hidden");
      el.classList.remove("block");
    }
  });

  if (window.lucide) {
    lucide.createIcons();
  }
}

async function loadInitialData() {
  try {
    // 1. Fetch Lab Status
    const statusRes = await fetch("/api/status");
    const statusData = await statusRes.json();
    updateStatusCards(statusData);

    // 2. Fetch Techniques
    const techRes = await fetch("/api/techniques");
    const techData = await techRes.json();
    STATE.techniques = techData.techniques || [];
    renderTechniqueCards(STATE.techniques);

    // 3. Fetch Detection Rules
    const rulesRes = await fetch("/api/rules");
    const rulesData = await rulesRes.json();
    STATE.rules = rulesData.rules || [];
    renderRulesList(STATE.rules);

    // 4. Fetch Queries (SPL & KQL)
    const queriesRes = await fetch("/api/queries");
    STATE.queries = await queriesRes.json();

    // 5. Fetch Telemetry Events
    const telemRes = await fetch("/api/telemetry");
    const telemData = await telemRes.json();
    STATE.telemetryEvents = telemData.events || [];
    renderTelemetryTable(STATE.telemetryEvents);

    // 6. Fetch Docs
    const docsRes = await fetch("/api/docs");
    const docsData = await docsRes.json();
    STATE.docs = docsData.docs || [];
    renderDocsList(STATE.docs);

    // 7. Render MITRE ATT&CK Grid
    renderMitreMatrix(STATE.techniques);

    // 8. Auto-run DaC tests to populate the results
    runDaCTests(true);

  } catch (err) {
    console.error("Error loading initial data:", err);
  }
}

function updateStatusCards(data) {
  if (!data) return;
  if (data.stats) {
    const elT = document.getElementById("stat-techniques-count");
    const elR = document.getElementById("stat-rules-count");
    if (elT) elT.innerText = data.stats.total_techniques;
    if (elR) elR.innerText = data.stats.detection_rules;
  }
}

// -----------------------------------------------------------------------------
// SPOTLIGHT & POPOVER INTERACTIVE TOUR
// -----------------------------------------------------------------------------

function startTour() {
  STATE.currentTourStep = 0;
  const overlay = document.getElementById("tour-spotlight-overlay");
  if (overlay) {
    overlay.classList.remove("hidden");
  }
  renderTourStep();
}

function endTour() {
  const overlay = document.getElementById("tour-spotlight-overlay");
  if (overlay) {
    overlay.classList.add("hidden");
  }
  localStorage.setItem("soc_range_tour_seen", "true");
}

function nextTourStep() {
  if (STATE.currentTourStep < STATE.tourSteps.length - 1) {
    STATE.currentTourStep++;
    renderTourStep();
  } else {
    endTour();
  }
}

function prevTourStep() {
  if (STATE.currentTourStep > 0) {
    STATE.currentTourStep--;
    renderTourStep();
  }
}

function renderTourStep() {
  const step = STATE.tourSteps[STATE.currentTourStep];
  if (!step) return;

  // 1. Auto-switch to relevant tab
  switchTab(step.tab);

  // 2. Render Text Content in Popover
  const badgeEl = document.getElementById("tour-step-badge");
  const targetTagEl = document.getElementById("tour-target-tag");
  const titleEl = document.getElementById("tour-step-title");
  const descEl = document.getElementById("tour-step-desc");
  const listEl = document.getElementById("tour-highlights-list");

  if (badgeEl) badgeEl.innerText = `Step ${STATE.currentTourStep + 1} of ${STATE.tourSteps.length}`;
  if (targetTagEl) targetTagEl.innerText = step.targetName || "Component";
  if (titleEl) titleEl.innerHTML = `<i data-lucide="crosshair" class="w-4 h-4 text-cyan-400 shrink-0"></i><span>${step.title}</span>`;
  if (descEl) descEl.innerText = step.desc;

  if (listEl && step.highlights) {
    listEl.innerHTML = step.highlights.map(h => `<li>${h}</li>`).join("");
  }

  // 3. Render Step Indicator Dots
  const dotsContainer = document.getElementById("tour-dots-container");
  if (dotsContainer) {
    dotsContainer.innerHTML = STATE.tourSteps.map((_, idx) => `
      <span class="w-2 h-2 rounded-full transition-all ${idx === STATE.currentTourStep ? 'bg-cyan-400 w-3' : 'bg-slate-700'}"></span>
    `).join("");
  }

  // 4. Update Navigation Buttons
  const prevBtn = document.getElementById("tour-prev-btn");
  if (prevBtn) prevBtn.disabled = (STATE.currentTourStep === 0);

  const nextText = document.getElementById("tour-next-text");
  if (nextText) {
    nextText.innerText = (STATE.currentTourStep === STATE.tourSteps.length - 1) ? "Finish Tour" : "Next Feature";
  }

  // 5. Scroll to target element and position the Spotlight cutout + Popover
  setTimeout(() => {
    positionSpotlightAndPopover();
    if (window.lucide) lucide.createIcons();
  }, 100);
}

function positionSpotlightAndPopover() {
  const step = STATE.tourSteps[STATE.currentTourStep];
  if (!step) return;

  const targetEl = document.getElementById(step.targetId);
  const spotlightBox = document.getElementById("tour-spotlight-box");
  const popoverCard = document.getElementById("tour-popover-card");

  if (!spotlightBox || !popoverCard) return;

  if (targetEl) {
    // Scroll smoothly so the target is centered
    targetEl.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });

    // Calculate exact target bounding box
    const rect = targetEl.getBoundingClientRect();
    const padding = 8;

    const spotTop = Math.max(0, rect.top - padding);
    const spotLeft = Math.max(0, rect.left - padding);
    const spotWidth = Math.min(window.innerWidth, rect.width + padding * 2);
    const spotHeight = rect.height + padding * 2;

    spotlightBox.style.top = `${spotTop}px`;
    spotlightBox.style.left = `${spotLeft}px`;
    spotlightBox.style.width = `${spotWidth}px`;
    spotlightBox.style.height = `${spotHeight}px`;
    spotlightBox.style.opacity = "1";

    // Position popover card smartly (below if space permits, otherwise above or to side)
    const popoverWidth = Math.min(440, window.innerWidth - 32);
    const popoverHeight = popoverCard.offsetHeight || 320;

    let popTop = spotTop + spotHeight + 16;
    let popLeft = Math.max(16, Math.min(window.innerWidth - popoverWidth - 16, spotLeft + (spotWidth / 2) - (popoverWidth / 2)));

    // If overflows bottom, place above the element
    if (popTop + popoverHeight > window.innerHeight - 20) {
      popTop = Math.max(20, spotTop - popoverHeight - 16);
    }

    // Boundary clamp
    popTop = Math.max(16, Math.min(window.innerHeight - popoverHeight - 16, popTop));

    popoverCard.style.top = `${popTop}px`;
    popoverCard.style.left = `${popLeft}px`;
    popoverCard.style.opacity = "1";

  } else {
    // Fallback: Center in screen if element not found
    spotlightBox.style.opacity = "0";
    popoverCard.style.top = "50%";
    popoverCard.style.left = "50%";
    popoverCard.style.transform = "translate(-50%, -50%)";
  }
}

// -----------------------------------------------------------------------------
// ADVERSARY EMULATION ACTIONS
// -----------------------------------------------------------------------------

function renderTechniqueCards(techniques) {
  const container = document.getElementById("techniques-cards-container");
  if (!container) return;

  container.innerHTML = techniques.map(tech => `
    <div class="p-5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between space-y-4">
      <div>
        <div class="flex items-center justify-between gap-2 mb-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-400 border border-red-500/30">
            ${tech.id}
          </span>
          <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300">
            ${tech.tactic}
          </span>
        </div>
        <h3 class="font-bold text-sm text-white mb-1.5">${tech.name}</h3>
        <p class="text-xs text-slate-400 leading-relaxed mb-3">${tech.description}</p>
        
        <div class="space-y-1 text-[11px] font-mono text-slate-400">
          <div class="flex items-center justify-between">
            <span>Detection Rule:</span>
            <span class="text-blue-400">${tech.detection_rule}</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Event Channel:</span>
            <span class="text-slate-300">${tech.telemetry_channel}</span>
          </div>
        </div>
      </div>

      <button onclick="triggerSimulation('${tech.id}')" class="w-full py-2 px-3 text-xs font-semibold rounded-lg bg-red-600/90 hover:bg-red-500 text-white shadow-md shadow-red-950/40 transition-all active:scale-95 flex items-center justify-center gap-1.5">
        <i data-lucide="play" class="w-3.5 h-3.5 fill-current"></i>
        <span>Execute ${tech.id}</span>
      </button>
    </div>
  `).join("");

  if (window.lucide) lucide.createIcons();
}

function setSimulationState(isRunning, activeTechnique = null) {
  STATE.isSimulating = isRunning;
  const fullBtn = document.getElementById("btn-full-sim");
  if (fullBtn) {
    fullBtn.disabled = isRunning;
    if (isRunning) {
      fullBtn.classList.add("opacity-60", "cursor-not-allowed");
      fullBtn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i><span>Emulating...</span>`;
    } else {
      fullBtn.classList.remove("opacity-60", "cursor-not-allowed");
      fullBtn.innerHTML = `<i data-lucide="zap" class="w-3.5 h-3.5"></i><span>Launch Full Attack</span>`;
    }
  }

  const execBtns = document.querySelectorAll("#techniques-cards-container button");
  execBtns.forEach(btn => {
    btn.disabled = isRunning;
    if (isRunning) {
      btn.classList.add("opacity-50", "cursor-not-allowed");
    } else {
      btn.classList.remove("opacity-50", "cursor-not-allowed");
    }
  });

  if (window.lucide) lucide.createIcons();
}

async function triggerSimulation(techniqueId) {
  if (STATE.isSimulating) {
    appendLocalLog("[!] A simulation campaign is already in progress. Please wait for completion.", "WARN");
    return;
  }

  const dryRun = document.getElementById("sim-dryrun")?.checked ?? true;
  const targetIp = document.getElementById("sim-target-ip")?.value || "192.168.56.10";

  setSimulationState(true, techniqueId);
  appendLocalLog(`[>] Initiating Emulation: ${techniqueId} (Target: ${targetIp}, DryRun: ${dryRun})...`, "INFO");

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        technique_id: techniqueId,
        target_ip: targetIp,
        dry_run: dryRun
      })
    });

    const data = await res.json();
    if (!res.ok) {
      appendLocalLog(`[!] Error executing simulation: ${data.detail || "Unknown error"}`, "ERROR");
    } else {
      appendLocalLog(`[✓] Completed ${techniqueId} emulation! Audit logged.`, "SUCCESS");
    }
  } catch (err) {
    appendLocalLog(`[!] Network error executing simulation: ${err}`, "ERROR");
  } finally {
    setSimulationState(false);
  }
}

async function triggerFullSimulation() {
  switchTab("adversary");
  await triggerSimulation("all");
}

function startLogStream() {
  if (STATE.logInterval) clearInterval(STATE.logInterval);
  
  STATE.logInterval = setInterval(async () => {
    try {
      const res = await fetch("/api/simulation/logs");
      const data = await res.json();
      if (data && data.logs) {
        renderTerminalLogs(data.logs);
      }
    } catch (e) {
      // silent
    }
  }, 1500);
}

function appendLocalLog(msg, level = "INFO") {
  const terminal = document.getElementById("simulation-terminal");
  const overviewConsole = document.getElementById("overview-console");
  
  const time = new Date().toLocaleTimeString();
  let colorClass = "text-slate-300";
  if (level === "ERROR") colorClass = "text-red-400 font-bold";
  if (level === "SUCCESS") colorClass = "text-emerald-400 font-bold";
  if (level === "WARN") colorClass = "text-amber-400";

  const row = `<div class="${colorClass}">[${time}] ${msg}</div>`;

  if (terminal) {
    terminal.innerHTML += row;
    terminal.scrollTop = terminal.scrollHeight;
  }
  if (overviewConsole) {
    overviewConsole.innerHTML += row;
    overviewConsole.scrollTop = overviewConsole.scrollHeight;
  }
}

function renderTerminalLogs(logs) {
  const terminal = document.getElementById("simulation-terminal");
  const overviewConsole = document.getElementById("overview-console");
  if (!terminal) return;

  if (logs.length === 0) return;

  const html = logs.map(l => {
    let colorClass = "text-slate-300";
    if (l.level === "ERROR") colorClass = "text-red-400 font-bold";
    if (l.level === "SUCCESS") colorClass = "text-emerald-400 font-semibold";
    if (l.level === "WARN") colorClass = "text-amber-400";
    return `<div class="${colorClass}">[${l.timestamp}] [${l.level}] ${l.message}</div>`;
  }).join("");

  terminal.innerHTML = html;
  terminal.scrollTop = terminal.scrollHeight;

  if (overviewConsole) {
    overviewConsole.innerHTML = html;
    overviewConsole.scrollTop = overviewConsole.scrollHeight;
  }
}

async function clearConsoleLogs() {
  await fetch("/api/simulation/clear-logs", { method: "POST" });
  const terminal = document.getElementById("simulation-terminal");
  const overviewConsole = document.getElementById("overview-console");
  if (terminal) terminal.innerHTML = `<div class="text-slate-500">> Console cleared. Ready.</div>`;
  if (overviewConsole) overviewConsole.innerHTML = `<div class="text-slate-500">[System] Console cleared.</div>`;
}

// -----------------------------------------------------------------------------
// DETECTION-AS-CODE & SIGMA LAB
// -----------------------------------------------------------------------------

async function runDaCTests(silent = false) {
  const btn = document.getElementById("btn-trigger-dac");
  if (btn && !silent) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i><span>Executing DaC Tests...</span>`;
    if (window.lucide) lucide.createIcons();
  }

  try {
    const res = await fetch("/api/rules/test", { method: "POST" });
    const data = await res.json();
    STATE.dacResults = data;
    renderDaCResults(data);
  } catch (err) {
    console.error("Error executing DaC test suite:", err);
  } finally {
    if (btn && !silent) {
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="play" class="w-4 h-4 fill-current"></i><span>Execute DaC Test Suite</span>`;
      if (window.lucide) lucide.createIcons();
    }
  }
}

function renderDaCResults(data) {
  if (!data) return;

  const badge = document.getElementById("dac-overall-badge");
  if (badge) {
    if (data.status === "PASSED") {
      badge.className = "px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
      badge.innerText = "ALL TESTS PASSING (100%)";
    } else {
      badge.className = "px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-red-500/10 text-red-400 border border-red-500/30";
      badge.innerText = "TESTS FAILED";
    }
  }

  const passRate = document.getElementById("dac-pass-rate");
  if (passRate) passRate.innerText = `${data.pass_rate_pct}%`;

  const fixturesCount = document.getElementById("dac-fixtures-count");
  if (fixturesCount) fixturesCount.innerText = `${data.total_fixtures} Fixtures`;

  const duration = document.getElementById("dac-duration");
  if (duration) duration.innerText = `${data.duration_ms} ms`;

  // Dynamically compute false positives across all rules
  const totalFp = Object.values(data.rule_stats || {}).reduce((acc, r) => acc + (r.false_positives || 0), 0);
  const fpCount = document.getElementById("dac-fp-count");
  if (fpCount) {
    fpCount.innerText = totalFp === 0 ? "0 Verified" : `${totalFp} Detected`;
    fpCount.className = totalFp === 0 ? "text-lg font-bold text-emerald-400 mt-1" : "text-lg font-bold text-red-400 mt-1";
  }

  // Also dynamically update Overview badge
  const overviewDac = document.getElementById("stat-dac-status");
  if (overviewDac) {
    overviewDac.innerText = `${data.pass_rate_pct}%`;
    overviewDac.className = `text-2xl font-bold ${data.status === "PASSED" ? "text-emerald-400" : "text-red-400"}`;
  }

  // Render evaluation table rows
  const tbody = document.getElementById("dac-test-tbody");
  if (tbody && data.fixture_evaluations) {
    tbody.innerHTML = data.fixture_evaluations.map(ev => `
      <tr class="hover:bg-slate-900/40">
        <td class="p-2.5">
          ${ev.passed 
            ? '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-bold">PASS</span>'
            : '<span class="px-2 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 font-bold">FAIL</span>'
          }
        </td>
        <td class="p-2.5 text-cyan-300">${ev.fixture_id}</td>
        <td class="p-2.5 text-slate-300 font-sans text-xs">${ev.description}</td>
        <td class="p-2.5 text-slate-400">${ev.provider} (${ev.event_id})</td>
        <td class="p-2.5 text-blue-400">${ev.expected_detections.join(", ") || "None (FP Filter)"}</td>
        <td class="p-2.5 ${ev.passed ? 'text-emerald-400 font-semibold' : 'text-red-400 font-bold'}">${ev.actual_detections.join(", ") || "None"}</td>
      </tr>
    `).join("");
  }
}

function renderRulesList(rules, activeIndex = 0) {
  const container = document.getElementById("rules-list-container");
  if (!container) return;

  // Update dynamic count badge
  const rulesBadge = document.getElementById("rules-badge");
  if (rulesBadge) {
    rulesBadge.innerText = `${rules.length} Rules`;
  }

  container.innerHTML = rules.map((r, idx) => `
    <button onclick="selectRule(${idx})" class="rule-item-btn w-full text-left p-2.5 rounded-lg ${idx === activeIndex ? 'bg-cyan-950/50 border-cyan-500/50' : 'bg-slate-950/60 hover:bg-slate-800/80 border-slate-800/80'} border transition-all group" data-rule-index="${idx}">
      <div class="flex items-center justify-between gap-1 mb-1">
        <span class="text-xs font-semibold ${idx === activeIndex ? 'text-cyan-300' : 'text-slate-200'} group-hover:text-cyan-400 truncate">${r.title || r.filename}</span>
        <span class="px-1.5 py-0.2 rounded text-[9px] font-mono ${getSeverityBadge(r.level)}">${r.level || 'info'}</span>
      </div>
      <div class="text-[11px] font-mono text-slate-400 truncate">${r.filename}</div>
    </button>
  `).join("");

  if (rules.length > 0) {
    selectRule(activeIndex >= 0 && activeIndex < rules.length ? activeIndex : 0);
  }
}

function getSeverityBadge(level) {
  level = (level || "").toLowerCase();
  if (level === "critical") return "bg-red-500/10 text-red-400 border border-red-500/30";
  if (level === "high") return "bg-rose-500/10 text-rose-400 border border-rose-500/30";
  if (level === "medium") return "bg-amber-500/10 text-amber-400 border border-amber-500/30";
  return "bg-blue-500/10 text-blue-400 border border-blue-500/30";
}

function selectRule(index) {
  const rule = STATE.rules[index];
  if (!rule) return;
  STATE.currentRule = rule;

  // Update active styling on rule buttons
  document.querySelectorAll(".rule-item-btn").forEach((btn, idx) => {
    if (idx === index) {
      btn.className = "rule-item-btn w-full text-left p-2.5 rounded-lg bg-cyan-950/50 border border-cyan-500/50 transition-all group";
    } else {
      btn.className = "rule-item-btn w-full text-left p-2.5 rounded-lg bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800/80 transition-all group";
    }
  });

  const titleEl = document.getElementById("current-rule-title");
  const metaEl = document.getElementById("current-rule-meta");
  if (titleEl) titleEl.innerText = rule.title || rule.filename;
  if (metaEl) metaEl.innerText = `ID: ${rule.id || 'N/A'} • Author: ${rule.author || 'Nayan Solanki'} • Status: ${rule.status || 'stable'}`;
  
  const editor = document.getElementById("rule-yaml-editor");
  if (editor) {
    editor.value = rule.raw_yaml || "";
  }

  // Populate SPL & KQL translations for this specific rule
  const splDisplay = document.getElementById("query-spl-display");
  const kqlDisplay = document.getElementById("query-kql-display");

  if (splDisplay) {
    splDisplay.innerText = getRelevantSpl(rule.filename);
  }
  if (kqlDisplay) {
    kqlDisplay.innerText = getRelevantKql(rule.filename);
  }
}

function extractQueryBlock(fullText, filename, delimiterRegex, prefix) {
  if (!fullText) return null;
  const baseName = filename.replace(/\.ya?ml$/, "");
  const blocks = fullText.split(delimiterRegex);
  for (const block of blocks) {
    if (block.includes(`Rule: ${filename}`) || block.includes(`Rule: ${baseName}`)) {
      return prefix + block.trim();
    }
  }
  return null;
}

function getRelevantSpl(filename) {
  if (!STATE.queries.splunk_spl) return "Query translation standard in detection-rules/splunk_queries.spl";
  const extracted = extractQueryBlock(STATE.queries.splunk_spl, filename, /\/\*\s*={5,}/, "/* ");
  return extracted || STATE.queries.splunk_spl;
}

function getRelevantKql(filename) {
  if (!STATE.queries.elastic_kql) return "Query translation standard in detection-rules/elastic_queries.kql";
  const extracted = extractQueryBlock(STATE.queries.elastic_kql, filename, /#\s*={5,}/, "# ");
  return extracted || STATE.queries.elastic_kql;
}

async function saveCurrentRule() {
  if (!STATE.currentRule) return;
  const editor = document.getElementById("rule-yaml-editor");
  const content = editor.value;

  try {
    const res = await fetch("/api/rules/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: STATE.currentRule.filename,
        yaml_content: content
      })
    });

    const data = await res.json();
    if (!res.ok) {
      alert("Error saving rule: " + (data.detail || "Validation failure"));
    } else {
      // 1. Immediately update current rule in-memory
      STATE.currentRule.raw_yaml = content;
      if (data.parsed) {
        Object.assign(STATE.currentRule, data.parsed);
      }

      // 2. Re-fetch all rules from backend to sync state
      const rulesRes = await fetch("/api/rules");
      const rulesData = await rulesRes.json();
      if (rulesData && rulesData.rules) {
        STATE.rules = rulesData.rules;
        const currentIdx = STATE.rules.findIndex(r => r.filename === STATE.currentRule.filename);
        renderRulesList(STATE.rules, currentIdx >= 0 ? currentIdx : 0);
      }

      appendLocalLog(`[✓] Rule '${STATE.currentRule.filename}' saved successfully! Re-running DaC test harness...`, "SUCCESS");
      await runDaCTests();
    }
  } catch (err) {
    alert("Network error saving rule: " + err);
  }
}

// -----------------------------------------------------------------------------
// SIEM TELEMETRY HUB
// -----------------------------------------------------------------------------

function renderTelemetryTable(events) {
  const tbody = document.getElementById("telemetry-tbody");
  if (!tbody) return;

  tbody.innerHTML = events.map((ev, idx) => {
    const eventData = ev.event_data || {};
    const detail = eventData.CommandLine || eventData.TargetImage || eventData.TargetFilename || eventData.Channel || "N/A";
    const user = eventData.User || eventData.TargetUserName || ev.computer || "SYSTEM";
    const detections = ev.expected_detections || [];

    return `
      <tr class="hover:bg-slate-900/50 transition-colors">
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
            ${ev.event_id || 'N/A'}
          </span>
        </td>
        <td class="p-3 text-slate-300 text-xs font-sans">${ev.provider || 'Windows'}</td>
        <td class="p-3 text-xs text-cyan-300 max-w-xs truncate" title="${detail}">${detail}</td>
        <td class="p-3 text-xs text-slate-400">${user}</td>
        <td class="p-3">
          ${detections.length > 0 
            ? detections.map(d => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 mr-1">${d}</span>`).join("")
            : '<span class="text-slate-500 text-[10px]">Baseline / Clean</span>'
          }
        </td>
        <td class="p-3 text-right">
          <button onclick="viewRawEvent(${idx})" class="px-2 py-1 text-[10px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300">View JSON</button>
        </td>
      </tr>
    `;
  }).join("");
}

function filterTelemetryTable() {
  const query = document.getElementById("telemetry-search").value.toLowerCase();
  const filtered = STATE.telemetryEvents.filter(ev => {
    const text = JSON.stringify(ev).toLowerCase();
    return text.includes(query);
  });
  renderTelemetryTable(filtered);
}

function viewRawEvent(index) {
  const ev = STATE.telemetryEvents[index];
  if (!ev) return;

  const viewer = document.getElementById("event-raw-viewer");
  const display = document.getElementById("event-raw-json");

  display.innerText = JSON.stringify(ev, null, 2);
  viewer.classList.remove("hidden");
  viewer.scrollIntoView({ behavior: "smooth" });
}

// -----------------------------------------------------------------------------
// MITRE ATT&CK MATRIX GRID
// -----------------------------------------------------------------------------

function renderMitreMatrix(techniques) {
  const grid = document.getElementById("mitre-matrix-grid");
  if (!grid) return;

  const tactics = [
    { name: "Initial Access", id: "TA0001" },
    { name: "Execution", id: "TA0002" },
    { name: "Persistence", id: "TA0003" },
    { name: "Defense Evasion", id: "TA0005" },
    { name: "Credential Access", id: "TA0006" }
  ];

  grid.innerHTML = tactics.map(tactic => {
    const covered = techniques.filter(t => t.tactic_id === tactic.id || t.tactic.toLowerCase() === tactic.name.toLowerCase());

    return `
      <div class="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2.5">
        <div class="flex items-center justify-between border-b border-slate-800 pb-2">
          <span class="text-xs font-bold text-slate-200">${tactic.name}</span>
          <span class="text-[10px] font-mono text-cyan-400">${tactic.id}</span>
        </div>

        <div class="space-y-2">
          ${covered.map(t => `
            <div onclick="switchTab('adversary')" class="p-2.5 rounded-lg bg-red-950/30 border border-red-500/30 hover:border-red-500 cursor-pointer transition-all">
              <div class="flex items-center justify-between text-[11px] font-mono font-bold text-red-400">
                <span>${t.id}</span>
                <span class="text-[10px] px-1 rounded bg-red-500/20 text-red-300">100% Score</span>
              </div>
              <div class="text-xs text-white font-medium mt-1">${t.name}</div>
              <div class="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <i data-lucide="shield-check" class="w-3 h-3 text-emerald-400"></i>
                <span class="truncate">${t.detection_rule}</span>
              </div>
            </div>
          `).join("")}

          ${covered.length === 0 ? '<div class="text-[11px] text-slate-600 italic py-2">No techniques emulated in current scope</div>' : ''}
        </div>
      </div>
    `;
  }).join("");

  if (window.lucide) lucide.createIcons();
}

// -----------------------------------------------------------------------------
// DOCUMENTATION LIBRARY
// -----------------------------------------------------------------------------

function renderDocsList(docs) {
  const container = document.getElementById("docs-list-container");
  if (!container) return;

  container.innerHTML = docs.map((d, idx) => `
    <button onclick="loadDoc('${d.id}')" class="w-full text-left p-2 rounded-lg bg-slate-950/60 hover:bg-slate-800 text-xs text-slate-300 hover:text-cyan-400 font-medium transition-all flex items-center justify-between">
      <span class="truncate">${d.title}</span>
      <i data-lucide="chevron-right" class="w-3.5 h-3.5 text-slate-500"></i>
    </button>
  `).join("");

  if (docs.length > 0) {
    loadDoc(docs[0].id);
  }
}

async function loadDoc(docId) {
  try {
    const res = await fetch(`/api/docs/${docId}`);
    const data = await res.json();
    const container = document.getElementById("doc-rendered-content");
    if (container && window.marked) {
      container.innerHTML = marked.parse(data.content || "");
    }
  } catch (err) {
    console.error("Error loading document:", err);
  }
}

// -----------------------------------------------------------------------------
// UTILITIES
// -----------------------------------------------------------------------------

function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText);
  alert("Query copied to clipboard!");
}

async function downloadReport() {
  try {
    const res = await fetch("/api/simulation-report");
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyber_range_audit_report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert("No audit report available to export yet.");
  }
}
