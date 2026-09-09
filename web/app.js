/**
 * SOC Cyber Range & Detection-as-Code (DaC) Command Center Client
 * Author: Nayan Solanki
 */

let STATE = {
  techniques: [],
  rules: [],
  currentRule: null,
  telemetryEvents: [],
  currentTelemetryFilter: "all",
  queries: {},
  docs: [],
  currentDoc: null,
  dacResults: null,
  isSimulating: false,
  isDemoRunning: false,
  demoTimer: null,
  logInterval: null,
  currentTourStep: 0,
  tourSteps: [
    {
      tab: "overview",
      targetId: "header-brand-section",
      targetName: "Cyber Range Overview",
      title: "1. Isolated Subnet & 3-Step Architecture",
      desc: "This platform is an enterprise-grade Cyber Range running inside an isolated Host-Only subnet (192.168.56.0/24). It demonstrates the complete Detection Engineering lifecycle: simulate attacks, capture telemetry, and test detection rules.",
      highlights: [
        "Host-Only Subnet: 192.168.56.0/24",
        "3 Active Nodes: Kali Linux (Attacker), Windows Server (Target), Ubuntu (SIEM)",
        "Industry Standards: MITRE ATT&CK v14 & Sigma Rule Standard"
      ]
    },
    {
      tab: "adversary",
      targetId: "adversary-top-controls",
      targetName: "Attack Simulator",
      title: "2. Safe Adversary Emulation",
      desc: "Simulate real-world adversary techniques (Password Spraying, Obfuscated PowerShell, LSASS Dumping). Safe Dry-Run mode lets you preview commands and test detections without altering system state.",
      highlights: [
        "5 modular MITRE ATT&CK techniques",
        "Configurable safe dry-run mode and target IP address",
        "Real-time terminal execution log stream"
      ]
    },
    {
      tab: "detection",
      targetId: "dac-test-banner",
      targetName: "Detection-as-Code",
      title: "3. Detection-as-Code & Sigma Multi-SIEM Engine",
      desc: "Treat detection rules like production software! Run automated CI/CD unit tests against synthetic telemetry to assert zero false positives. Inspect Sigma rules and auto-generate Splunk (SPL) & Elastic (KQL) queries.",
      highlights: [
        "Automated regression testing for 0 False Positives",
        "Live YAML rule editor with validation",
        "1-click copy for Splunk SPL and Elasticsearch KQL"
      ]
    },
    {
      tab: "telemetry",
      targetId: "telemetry-header-bar",
      targetName: "SIEM Event Logs",
      title: "4. Forensic Event Logs & Telemetry Hub",
      desc: "Inspect low-level Windows Security and Sysmon 4.90 event logs shipped into the SIEM. Use quick filter pills to isolate failed logins (4625), process spawns (Sysmon 1), or LSASS dumps (Sysmon 10).",
      highlights: [
        "Windows Security Event 4625, 4104, 1102 & Sysmon 1, 10, 12",
        "Quick filter chips by attack type",
        "Forensic raw JSON inspection modal"
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

  // Handle window resizing to keep spotlight attached
  window.addEventListener("resize", () => {
    const overlay = document.getElementById("tour-spotlight-overlay");
    if (overlay && !overlay.classList.contains("hidden")) {
      positionSpotlightAndPopover();
    }
  });
});

// -----------------------------------------------------------------------------
// TAB NAVIGATION
// -----------------------------------------------------------------------------

function switchTab(tabId) {
  // Support aliases for consolidated map
  if (tabId === "matrix" || tabId === "topology") {
    tabId = "map";
  }

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

function toggleExplainer() {
  const content = document.getElementById("explainer-content");
  const chevron = document.getElementById("explainer-chevron");
  if (!content) return;
  
  const isHidden = content.classList.contains("hidden");
  if (isHidden) {
    content.classList.remove("hidden");
    if (chevron) chevron.style.transform = "rotate(180deg)";
  } else {
    content.classList.add("hidden");
    if (chevron) chevron.style.transform = "rotate(0deg)";
  }
}

// -----------------------------------------------------------------------------
// INITIAL DATA LOADING
// -----------------------------------------------------------------------------

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

    // 8. Auto-run DaC tests silently to populate initial metrics
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
// INTERACTIVE 3-STEP LIVE DEMONSTRATION
// -----------------------------------------------------------------------------

async function runInteractiveDemo() {
  if (STATE.isDemoRunning || STATE.isSimulating) return;
  STATE.isDemoRunning = true;

  const banner = document.getElementById("demo-banner");
  const stepIndicator = document.getElementById("demo-step-indicator");
  const stepTitle = document.getElementById("demo-step-title");
  const stepDesc = document.getElementById("demo-step-desc");

  if (banner) banner.classList.remove("hidden");

  // --- STAGE 1: Adversary Emulation ---
  switchTab("adversary");
  if (stepIndicator) stepIndicator.innerText = "Step 1 of 3 (Offense)";
  if (stepTitle) stepTitle.innerText = "Simulating T1110.003 Password Spraying";
  if (stepDesc) stepDesc.innerText = "Executing realistic brute-force authentication against Windows target 192.168.56.10...";

  appendLocalLog("[Demo] ═══════════════════════════════════════════════════════════════", "INFO");
  appendLocalLog("[Demo] Starting Live 3-Step Demonstration: Attack ➔ Log ➔ Detection", "INFO");
  appendLocalLog("[Demo] Step 1: Simulating T1110.003 Password Spraying...", "INFO");

  await triggerSimulation("T1110.003");

  // Wait 2.5s for user to observe
  await new Promise(resolve => { STATE.demoTimer = setTimeout(resolve, 2500); });
  if (!STATE.isDemoRunning) return;

  // --- STAGE 2: Telemetry Ingestion ---
  switchTab("telemetry");
  setTelemetryFilter("4625");
  if (stepIndicator) stepIndicator.innerText = "Step 2 of 3 (Telemetry)";
  if (stepTitle) stepTitle.innerText = "Ingesting Security Event 4625";
  if (stepDesc) stepDesc.innerText = "Windows Security log generated Event ID 4625 (LogonType 10 / RDP) and shipped to SIEM via Winlogbeat.";

  appendLocalLog("[Demo] Step 2: Telemetry captured! Windows Event ID 4625 ingested.", "INFO");

  // Wait 3s
  await new Promise(resolve => { STATE.demoTimer = setTimeout(resolve, 3000); });
  if (!STATE.isDemoRunning) return;

  // --- STAGE 3: Detection-as-Code ---
  switchTab("detection");
  if (stepIndicator) stepIndicator.innerText = "Step 3 of 3 (Defense)";
  if (stepTitle) stepTitle.innerText = "Evaluating Sigma Rule & Generating SIEM Queries";
  if (stepDesc) stepDesc.innerText = "Rule 'rdp_brute_force.yaml' matched the attack pattern! Auto-generating Splunk SPL & Elastic KQL queries.";

  // Select the matching rule
  const ruleIdx = STATE.rules.findIndex(r => r.filename.includes("rdp_brute_force") || (r.title && r.title.toLowerCase().includes("brute force")));
  if (ruleIdx >= 0) {
    selectRule(ruleIdx);
  }

  appendLocalLog("[Demo] Step 3: Detection-as-Code asserted! Rule matched with 0 false positives.", "SUCCESS");
  appendLocalLog("[Demo] ═══════════════════════════════════════════════════════════════", "SUCCESS");

  // Wait 3.5s then show completion
  await new Promise(resolve => { STATE.demoTimer = setTimeout(resolve, 3500); });
  if (!STATE.isDemoRunning) return;

  if (stepIndicator) stepIndicator.innerText = "Complete";
  if (stepTitle) stepTitle.innerText = "🎉 3-Step Live Demo Succeeded!";
  if (stepDesc) stepDesc.innerText = "All 3 stages (Attack ➔ Log ➔ Detection) verified with 100% fidelity. Feel free to explore freely!";

  setTimeout(() => {
    stopInteractiveDemo();
  }, 5000);
}

function stopInteractiveDemo() {
  STATE.isDemoRunning = false;
  if (STATE.demoTimer) clearTimeout(STATE.demoTimer);
  const banner = document.getElementById("demo-banner");
  if (banner) banner.classList.add("hidden");
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
    targetEl.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });

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

    const popoverWidth = Math.min(440, window.innerWidth - 32);
    const popoverHeight = popoverCard.offsetHeight || 320;

    let popTop = spotTop + spotHeight + 16;
    let popLeft = Math.max(16, Math.min(window.innerWidth - popoverWidth - 16, spotLeft + (spotWidth / 2) - (popoverWidth / 2)));

    if (popTop + popoverHeight > window.innerHeight - 20) {
      popTop = Math.max(20, spotTop - popoverHeight - 16);
    }

    popTop = Math.max(16, Math.min(window.innerHeight - popoverHeight - 16, popTop));

    popoverCard.style.top = `${popTop}px`;
    popoverCard.style.left = `${popLeft}px`;
    popoverCard.style.opacity = "1";

  } else {
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
        
        <div class="space-y-1 text-[11px] font-mono text-slate-400 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
          <div class="flex items-center justify-between">
            <span class="text-slate-400">Detection:</span>
            <span class="text-blue-400 font-semibold truncate max-w-[170px]" title="${tech.detection_rule}">${tech.detection_rule}</span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-slate-400">Target Log:</span>
            <span class="text-emerald-400 truncate max-w-[170px]" title="${tech.telemetry_channel}">${tech.telemetry_channel}</span>
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
  if (STATE.isSimulating && !STATE.isDemoRunning) {
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

  // Update Overview badge
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
      STATE.currentRule.raw_yaml = content;
      if (data.parsed) {
        Object.assign(STATE.currentRule, data.parsed);
      }

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
// SIEM TELEMETRY HUB & FORENSICS
// -----------------------------------------------------------------------------

function setTelemetryFilter(filterKey) {
  STATE.currentTelemetryFilter = filterKey;

  // Update filter pill UI
  document.querySelectorAll(".filter-chip").forEach(chip => {
    if (chip.getAttribute("data-filter") === filterKey) {
      chip.classList.add("active");
    } else {
      chip.classList.remove("active");
    }
  });

  filterTelemetryTable();
}

function renderTelemetryTable(events) {
  const tbody = document.getElementById("telemetry-tbody");
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="p-6 text-center text-slate-500 italic">
          No telemetry events match current filter.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = events.map((ev, idx) => {
    const eventData = ev.event_data || {};
    const detail = eventData.CommandLine || eventData.TargetImage || eventData.TargetFilename || eventData.Channel || "N/A";
    const user = eventData.User || eventData.TargetUserName || ev.computer || "SYSTEM";
    const detections = ev.expected_detections || [];

    // Find original index in STATE.telemetryEvents
    const origIdx = STATE.telemetryEvents.indexOf(ev);
    const viewIdx = origIdx >= 0 ? origIdx : idx;

    return `
      <tr class="hover:bg-slate-900/50 transition-colors">
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 font-mono">
            ${ev.event_id || 'N/A'}
          </span>
        </td>
        <td class="p-3 text-slate-300 text-xs font-sans">${ev.provider || 'Windows'}</td>
        <td class="p-3 text-xs text-cyan-300 max-w-xs truncate" title="${detail}">${detail}</td>
        <td class="p-3 text-xs text-slate-400">${user}</td>
        <td class="p-3">
          ${detections.length > 0 
            ? detections.map(d => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 mr-1 font-mono">${d}</span>`).join("")
            : '<span class="text-slate-500 text-[10px]">Clean Baseline</span>'
          }
        </td>
        <td class="p-3 text-right">
          <button onclick="viewRawEvent(${viewIdx})" class="px-2.5 py-1 text-[11px] font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors">
            Inspect JSON
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function filterTelemetryTable() {
  const searchInput = document.getElementById("telemetry-search");
  const query = (searchInput ? searchInput.value : "").toLowerCase();
  const filter = STATE.currentTelemetryFilter;

  const filtered = STATE.telemetryEvents.filter(ev => {
    // 1. Check category filter
    const evId = String(ev.event_id || "");
    if (filter === "4625" && evId !== "4625") return false;
    if (filter === "1" && evId !== "1") return false;
    if (filter === "10" && evId !== "10") return false;
    if (filter === "1102" && evId !== "1102") return false;
    if (filter === "clean" && (ev.expected_detections || []).length > 0) return false;

    // 2. Check search input query
    if (query) {
      const text = JSON.stringify(ev).toLowerCase();
      if (!text.includes(query)) return false;
    }

    return true;
  });

  renderTelemetryTable(filtered);
}

function viewRawEvent(index) {
  const ev = STATE.telemetryEvents[index];
  if (!ev) return;

  const modal = document.getElementById("event-raw-modal");
  const display = document.getElementById("event-raw-json");

  if (display) display.innerText = JSON.stringify(ev, null, 2);
  if (modal) modal.classList.remove("hidden");
}

function closeRawModal() {
  const modal = document.getElementById("event-raw-modal");
  if (modal) modal.classList.add("hidden");
}

function copyJsonToClipboard() {
  const display = document.getElementById("event-raw-json");
  if (!display) return;
  navigator.clipboard.writeText(display.innerText);
  alert("Forensic JSON copied to clipboard!");
}

// -----------------------------------------------------------------------------
// MITRE ATT&CK MATRIX & TOPOLOGY
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

  container.innerHTML = docs.map(d => `
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
