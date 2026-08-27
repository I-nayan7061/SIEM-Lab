# Detection Engineering Standard Operating Procedure (SOP)

**Author:** Nayan Solanki (Senior Detection Engineering Portfolio)  
**Standard:** Enterprise Detection-as-Code (DaC) Lifecycle  

---

## 1. Detection Rule Lifecycle (DaC Workflow)

```
 ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
 │  1. Research │ ───► │  2. Develop  │ ───► │ 3. Unit Test │ ───► │  4. Canary   │ ───► │5. Production │
 │ Threat Intel │      │  Sigma YAML  │      │ Synthetic CI │      │ Tuning & FPR │      │ Active Alert │
 └──────────────┘      └──────────────┘      └──────────────┘      └──────────────┘      └──────────────┘
```

### Stage 1: Threat Intelligence & Adversary Profiling
- Identify new adversary technique or sub-technique from threat reports or red team simulation.
- Determine the minimum required telemetry sources (e.g. Sysmon Event 10, Security 4625).

### Stage 2: Rule Authoring (Sigma Standard)
- Rules must be authored in generic **Sigma YAML** format to ensure portability across SIEM platforms (Splunk, Elastic, Sentinel).
- Every rule must specify:
  - Unique UUID v4 `id`
  - Explicit MITRE ATT&CK `tags` (e.g. `attack.t1059.001`)
  - Target `logsource` (product, service, category)
  - Clear `falsepositives` tuning exclusions

### Stage 3: Automated Unit Testing (CI/CD)
- Execute `pytest tests/test_detection_rules.py` in GitHub Actions.
- Ensure 100% pass rate on True Positive assertion and False Positive suppression test cases.

### Stage 4: Canary / Silent Mode Deployment
- Deploy the rule in SIEM as a **Silent Alert** (Log-only, no paging).
- Monitor for 7 days to calculate the **False Positive Rate (FPR)**:
  $$\text{FPR} = \frac{\text{False Positive Triggers}}{\text{Total Triggers}} \times 100$$
- Target: $\text{FPR} \le 5\%$ before production promotion.

### Stage 5: Production Deployment & Continuous Tuning
- Promote to active SOC alert with assigned Severity and Tier 1 Runbook link.
- Review rule quarterly or upon infrastructure architecture changes.

---

## 2. Severity & SLA Escalation Matrix

| Severity Level | MTTD Benchmark (Mean Time to Detect) | MTTA (Mean Time to Acknowledge) | Escalation Action |
| :--- | :--- | :--- | :--- |
| **Critical** | $\le 2$ minutes | $\le 10$ minutes | Automated host network quarantine + On-call SOC escalation |
| **High** | $\le 5$ minutes | $\le 30$ minutes | SOC Tier 1 analyst investigation + Ticket creation |
| **Medium** | $\le 15$ minutes | $\le 2$ hours | Aggregated anomaly report / Threat hunting backlog |
| **Low / Info** | $\le 1$ hour | $\le 24$ hours | Audit record / Context enrichment |
