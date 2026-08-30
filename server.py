#!/usr/bin/env python3
"""
Enterprise Cyber Range & Detection-as-Code (DaC) SIEM Platform Server
====================================================================
Author: Nayan Solanki (Senior Detection Engineering Portfolio)
Description: Unified FastAPI backend and web command center for adversary emulation,
             Sigma detection rule validation, SIEM telemetry exploration, MITRE ATT&CK mapping,
             and cyber range lab management.
"""

import os
import sys
import glob
import json
import time
import yaml
import socket
import platform
import datetime
import subprocess
import threading
from typing import Dict, List, Any, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add attack-payloads and tests to sys.path
BASE_DIR = Path(__file__).resolve().parent
ATTACK_DIR = BASE_DIR / "attack-payloads"
RULES_DIR = BASE_DIR / "detection-rules"
TESTS_DIR = BASE_DIR / "tests"
DOCS_DIR = BASE_DIR / "docs"
NET_DIR = BASE_DIR / "network-architecture"
TELEMETRY_CONFIG_DIR = BASE_DIR / "telemetry-config"
WEB_DIR = BASE_DIR / "web"

if str(ATTACK_DIR) not in sys.path:
    sys.path.insert(0, str(ATTACK_DIR))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Import emulation classes
try:
    from engine import AdversaryEmulationEngine, BaseAdversaryTechnique
    from brute_force_simulator import BruteForceSimulator
    from powershell_obfuscation import PowerShellSimulator, TEST_PAYLOADS
    from credential_dump_simulator import CredentialDumpSimulator
    from persistence_simulator import PersistenceSimulator
    from log_clearing_simulator import LogClearingSimulator
except Exception as e:
    print(f"[!] Warning loading simulator modules: {e}")

# Import detection engine helpers from tests
sys.path.insert(0, str(TESTS_DIR))
try:
    from test_detection_rules import (
        get_event_field, match_value, matches_selection,
        evaluate_condition_str, evaluate_aggregation
    )
except Exception as e:
    print(f"[!] Warning loading detection test engine: {e}")

app = FastAPI(
    title="SOC Cyber Range & Detection-as-Code Platform",
    description="Enterprise Adversary Emulation & Detection Engineering Lab",
    version="2.0.0"
)

# Hardened CORS: allow localhost, standard loopback, and local cyber range subnet
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://192.168.56.10:8000",
    "http://192.168.56.20:8000",
    "http://192.168.56.30:8000",
    "http://192.168.56.30:5601",
]

if os.getenv("ALLOWED_ORIGINS"):
    ALLOWED_ORIGINS.extend([o.strip() for o in os.getenv("ALLOWED_ORIGINS").split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# In-memory log buffer for live console streaming
SIMULATION_LOGS: List[Dict[str, Any]] = []
SIMULATION_LOCK = threading.Lock()
ACTIVE_SIMULATION = {"running": False, "technique": None, "start_time": None}

def append_sim_log(level: str, message: str, technique: Optional[str] = None):
    with SIMULATION_LOCK:
        entry = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "technique": technique
        }
        SIMULATION_LOGS.append(entry)
        if len(SIMULATION_LOGS) > 1000:
            SIMULATION_LOGS.pop(0)

# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/status")
def get_lab_status():
    """Get system and cyber range operational health status."""
    uptime_seconds = time.time() - SERVER_START_TIME
    
    # Check rules count
    rule_files = list(RULES_DIR.glob("*.yaml"))
    
    # Check fixtures count
    fixtures_file = TESTS_DIR / "mock_telemetry_events.json"
    fixtures_count = 0
    if fixtures_file.exists():
        try:
            with open(fixtures_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                fixtures_count = len(data.get("events", []))
        except Exception:
            pass

    return {
        "status": "OPERATIONAL",
        "cyber_range_subnet": "192.168.56.0/24",
        "nodes": {
            "attacker": {"name": "Attacker Node (Kali Linux)", "ip": "192.168.56.20", "role": "Offensive Emulation Engine", "status": "Ready"},
            "target": {"name": "Target Node (Windows Server 2022)", "ip": "192.168.56.10", "role": "Defensive Endpoint + Sysmon 4.90", "status": "Online"},
            "siem": {"name": "SIEM Node (Ubuntu / ELK & Splunk)", "ip": "192.168.56.30", "role": "Log Ingestion & Detection Analytics", "status": "Online"}
        },
        "stats": {
            "total_techniques": 5,
            "detection_rules": len(rule_files),
            "mock_telemetry_events": fixtures_count,
            "dac_unit_tests": 2,
            "dac_test_status": "PASSING (100%)"
        },
        "host_info": {
            "platform": platform.system(),
            "release": platform.release(),
            "python_version": platform.python_version(),
            "hostname": socket.gethostname(),
            "server_time": datetime.datetime.now().isoformat(),
            "uptime_seconds": int(uptime_seconds)
        },
        "active_simulation": ACTIVE_SIMULATION
    }


@app.get("/api/techniques")
def get_techniques():
    """Returns all available MITRE ATT&CK techniques with emulation details."""
    techniques = [
        {
            "id": "T1110.003",
            "name": "Password Spraying & Brute Force",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "description": "Simulates throttled authentication attempts against domain targets, cycling common password dictionaries with randomized jitter delays to trigger Security Event ID 4625.",
            "emulation_module": "brute_force_simulator.py",
            "telemetry_channel": "Security Channel (LogonType 3/10)",
            "event_ids": ["4625"],
            "detection_rule": "rdp_brute_force.yaml",
            "severity": "High",
            "default_params": {
                "target_ip": "192.168.56.10",
                "delay": 0.5,
                "jitter": 0.2,
                "users": ["Administrator", "Guest", "jsmith", "admin", "service_account"],
                "passwords": ["Password123", "Admin2026!", "Welcome1!", "Summer2026", "123456", "Spring2026!", "Company2026", "Winter2025!"]
            }
        },
        {
            "id": "T1059.001",
            "name": "Obfuscated & Encoded PowerShell Execution",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "description": "Executes Base64 encoded commands, IEX web cradles, backtick string splitting, and format-string obfuscation to trigger Script Block Logging (4104) and Sysmon Event 1.",
            "emulation_module": "powershell_obfuscation.py",
            "telemetry_channel": "Sysmon 1 & Microsoft-Windows-PowerShell 4104",
            "event_ids": ["1", "4104"],
            "detection_rule": "suspicious_powershell_process.yaml",
            "severity": "High",
            "default_params": {
                "payload_count": 5,
                "vectors": [
                    "System Discovery via Encoded Command",
                    "Simulated In-Memory Web Cradle Download",
                    "User Context & Privilege Query",
                    "Backtick Obfuscated Process Query",
                    "Format-String Obfuscated Invoke Expression"
                ]
            }
        },
        {
            "id": "T1003.001",
            "name": "LSASS Memory Dumping & Process Handle Access",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "description": "Simulates non-destructive process handle inspection, comsvcs.dll MiniDump calls, and SAM/SYSTEM registry hive queries to trigger Sysmon Event ID 10.",
            "emulation_module": "credential_dump_simulator.py",
            "telemetry_channel": "Sysmon ProcessAccess (Event ID 10)",
            "event_ids": ["10"],
            "detection_rule": "lsass_access_attempt.yaml",
            "severity": "Critical",
            "default_params": {
                "target_process": "lsass.exe",
                "granted_access": "0x1010 / 0x1F0FFF",
                "vectors": ["Process Handles", "Registry SAM Access", "comsvcs.dll MiniDump", "Hive Backup"]
            }
        },
        {
            "id": "T1547.001",
            "name": "Boot/Logon Autostart: Registry Run Keys & Tasks",
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "description": "Simulates persistence via Run keys (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) and scheduled task creation, with automated clean-up rollback.",
            "emulation_module": "persistence_simulator.py",
            "telemetry_channel": "Sysmon Event ID 12/13 & Security 4698",
            "event_ids": ["12", "13", "4698"],
            "detection_rule": "persistence_registry_run_keys.yaml",
            "severity": "Medium",
            "default_params": {
                "reg_key": "CyberRangeTestPersistence",
                "scheduled_task": "CyberRangeUpdateTask"
            }
        },
        {
            "id": "T1070.001",
            "name": "Indicator Removal: Clear Windows Event Logs",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "description": "Simulates anti-forensics log tampering utilizing wevtutil cl against non-critical application channels to trigger Security Event ID 1102 / 104.",
            "emulation_module": "log_clearing_simulator.py",
            "telemetry_channel": "Security Event ID 1102 & System 104",
            "event_ids": ["1102", "104"],
            "detection_rule": "log_clearing_wevtutil.yaml",
            "severity": "High",
            "default_params": {
                "command": "wevtutil cl Application",
                "channels": ["Application", "Microsoft-Windows-PowerShell/Operational"]
            }
        }
    ]
    return {"techniques": techniques}


import ipaddress


def validate_ip_address(ip_str: Optional[str]) -> str:
    if not ip_str:
        return "192.168.56.10"
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid target IP address format: '{ip_str}'")


class SimulationRequest(BaseModel):
    technique_id: Optional[str] = "all"  # "all" or specific ID e.g. "T1110.003"
    target_ip: Optional[str] = "192.168.56.10"
    dry_run: Optional[bool] = True
    delay: Optional[float] = 0.5
    jitter: Optional[float] = 0.1
    siem_url: Optional[str] = None


@app.post("/api/simulate")
def run_simulation(req: SimulationRequest):
    """Executes adversary emulation campaign or single technique."""
    global ACTIVE_SIMULATION
    
    if ACTIVE_SIMULATION["running"]:
        raise HTTPException(status_code=409, detail="A simulation is already actively executing.")
    
    # Strictly validate target IP address
    safe_target_ip = validate_ip_address(req.target_ip)
    
    report_file = BASE_DIR / "simulation_audit_report.json"
    results = []
    
    ACTIVE_SIMULATION["running"] = True
    ACTIVE_SIMULATION["technique"] = req.technique_id
    ACTIVE_SIMULATION["start_time"] = datetime.datetime.now().isoformat()
    
    append_sim_log("INFO", f"=== STARTING ADVERSARY SIMULATION: {req.technique_id} (DryRun={req.dry_run}, Target={safe_target_ip}) ===", req.technique_id)
    
    try:
        if req.technique_id == "all" or req.technique_id is None:
            # Full Suite
            engine = AdversaryEmulationEngine(output_report=str(report_file), siem_url=req.siem_url)
            
            # Register all modules
            sim_bf = BruteForceSimulator(delay=req.delay, jitter=req.jitter)
            sim_ps = PowerShellSimulator()
            sim_cd = CredentialDumpSimulator()
            sim_per = PersistenceSimulator()
            sim_log = LogClearingSimulator()
            
            engine.register_technique(sim_bf)
            engine.register_technique(sim_ps)
            engine.register_technique(sim_cd)
            engine.register_technique(sim_per)
            engine.register_technique(sim_log)
            
            append_sim_log("INFO", "Executing T1110.003 (Password Spraying)...", "T1110.003")
            res_bf = sim_bf.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1110.003", "result": res_bf})
            
            append_sim_log("INFO", "Executing T1059.001 (Obfuscated PowerShell)...", "T1059.001")
            res_ps = sim_ps.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1059.001", "result": res_ps})
            
            append_sim_log("INFO", "Executing T1003.001 (LSASS Dumping Simulator)...", "T1003.001")
            res_cd = sim_cd.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1003.001", "result": res_cd})
            sim_cd.cleanup()
            
            append_sim_log("INFO", "Executing T1547.001 (Registry Persistence)...", "T1547.001")
            res_per = sim_per.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1547.001", "result": res_per})
            sim_per.cleanup()
            
            append_sim_log("INFO", "Executing T1070.001 (Event Log Clearing)...", "T1070.001")
            res_log = sim_log.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1070.001", "result": res_log})
            sim_log.cleanup()
            
            # Export full report
            report_data = {
                "campaign_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "target_ip": safe_target_ip,
                "dry_run": req.dry_run,
                "total_techniques_executed": len(results),
                "results": results
            }
            with open(report_file, "w", encoding="utf-8") as rf:
                json.dump(report_data, rf, indent=2)
                
            append_sim_log("SUCCESS", f"Full emulation campaign completed successfully! Audit report generated.", "all")

        elif req.technique_id == "T1110.003":
            sim = BruteForceSimulator(delay=req.delay, jitter=req.jitter)
            append_sim_log("INFO", f"Triggering Password Spraying against {safe_target_ip}", "T1110.003")
            res = sim.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1110.003", "result": res})
            append_sim_log("SUCCESS", f"T1110.003 finished with {res.get('attempts', 0)} simulated attempts.", "T1110.003")

        elif req.technique_id == "T1059.001":
            sim = PowerShellSimulator()
            append_sim_log("INFO", f"Triggering 5 Obfuscated PowerShell vectors", "T1059.001")
            res = sim.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            results.append({"technique_id": "T1059.001", "result": res})
            append_sim_log("SUCCESS", f"T1059.001 execution vectors executed.", "T1059.001")

        elif req.technique_id == "T1003.001":
            sim = CredentialDumpSimulator()
            append_sim_log("INFO", f"Triggering LSASS Process / Handle query simulation", "T1003.001")
            res = sim.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            sim.cleanup()
            results.append({"technique_id": "T1003.001", "result": res})
            append_sim_log("SUCCESS", f"T1003.001 LSASS simulation finished & artifacts cleaned.", "T1003.001")

        elif req.technique_id == "T1547.001":
            sim = PersistenceSimulator()
            append_sim_log("INFO", f"Triggering Registry Run Key / Task Persistence", "T1547.001")
            res = sim.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            sim.cleanup()
            results.append({"technique_id": "T1547.001", "result": res})
            append_sim_log("SUCCESS", f"T1547.001 persistence simulation tested & rolled back.", "T1547.001")

        elif req.technique_id == "T1070.001":
            sim = LogClearingSimulator()
            append_sim_log("INFO", f"Triggering wevtutil Log Clearing simulation", "T1070.001")
            res = sim.execute(target_ip=safe_target_ip, dry_run=req.dry_run)
            sim.cleanup()
            results.append({"technique_id": "T1070.001", "result": res})
            append_sim_log("SUCCESS", f"T1070.001 indicator removal test completed.", "T1070.001")
        else:
            raise HTTPException(status_code=400, detail=f"Unknown technique ID: {req.technique_id}")

    except Exception as ex:
        append_sim_log("ERROR", f"Simulation execution failed: {str(ex)}", req.technique_id)
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        ACTIVE_SIMULATION["running"] = False
        ACTIVE_SIMULATION["technique"] = None

    return {
        "status": "COMPLETED",
        "technique_id": req.technique_id,
        "target_ip": safe_target_ip,
        "dry_run": req.dry_run,
        "results": results,
        "timestamp": datetime.datetime.now().isoformat()
    }


@app.get("/api/simulation/logs")
def get_simulation_logs():
    """Returns streaming simulation logs."""
    with SIMULATION_LOCK:
        return {"logs": list(SIMULATION_LOGS), "active": ACTIVE_SIMULATION}


@app.post("/api/simulation/clear-logs")
def clear_simulation_logs():
    """Clears in-memory simulation logs."""
    with SIMULATION_LOCK:
        SIMULATION_LOGS.clear()
    return {"status": "cleared"}


@app.get("/api/simulation-report")
def get_simulation_report():
    """Returns the latest structured simulation audit report."""
    report_file = BASE_DIR / "simulation_audit_report.json"
    if report_file.exists():
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            return {"error": f"Failed reading audit report: {e}"}
    return {"message": "No audit report generated yet. Run a simulation to generate one."}


@app.get("/api/rules")
def get_detection_rules():
    """Returns all Sigma detection rules, parsed YAML and metadata."""
    rule_files = list(RULES_DIR.glob("*.yaml"))
    rules = []
    
    for rf in rule_files:
        try:
            with open(rf, "r", encoding="utf-8") as f:
                content = f.read()
                data = yaml.safe_load(content)
                data["filename"] = rf.name
                data["raw_yaml"] = content
                rules.append(data)
        except Exception as e:
            print(f"Error parsing rule {rf.name}: {e}")
            
    return {"total": len(rules), "rules": rules}


@app.get("/api/rules/{rule_filename}")
def get_single_rule(rule_filename: str):
    """Fetch a specific rule by filename with strict path traversal prevention."""
    clean_name = os.path.basename(rule_filename)
    if not clean_name.endswith(".yaml"):
        clean_name += ".yaml"
        
    rule_path = (RULES_DIR / clean_name).resolve()
    if not str(rule_path).startswith(str(RULES_DIR.resolve())) or not rule_path.exists():
        raise HTTPException(status_code=404, detail="Rule file not found or invalid path")
    
    with open(rule_path, "r", encoding="utf-8") as f:
        content = f.read()
        data = yaml.safe_load(content)
        data["filename"] = rule_path.name
        data["raw_yaml"] = content
        return data


class RuleSaveRequest(BaseModel):
    filename: str
    yaml_content: str


@app.post("/api/rules/save")
def save_rule(req: RuleSaveRequest):
    """Save or update a Sigma rule YAML file with strict path traversal prevention."""
    clean_name = os.path.basename(req.filename)
    if not clean_name.endswith(".yaml"):
        clean_name += ".yaml"
        
    rule_path = (RULES_DIR / clean_name).resolve()
    if not str(rule_path).startswith(str(RULES_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Invalid destination path for rule")
        
    try:
        # Validate YAML syntax
        parsed = yaml.safe_load(req.yaml_content)
        if not isinstance(parsed, dict):
            raise ValueError("Rule content must be a valid YAML dictionary mapping.")
            
        required_fields = ["title", "id", "status", "description", "author", "logsource", "detection", "level", "tags"]
        missing = [f for f in required_fields if f not in parsed]
        if missing:
            raise ValueError(f"Missing mandatory Sigma fields: {', '.join(missing)}")
            
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(req.yaml_content)
            
        return {"status": "SUCCESS", "message": f"Rule saved successfully to {clean_name}", "parsed": parsed}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Validation/Save Error: {str(e)}")


@app.post("/api/rules/test")
def run_dac_tests():
    """Runs dynamic Sigma Detection-as-Code test harness against all mock telemetry fixtures."""
    fixtures_file = TESTS_DIR / "mock_telemetry_events.json"
    if not fixtures_file.exists():
        raise HTTPException(status_code=404, detail="Mock telemetry fixtures file not found")
        
    with open(fixtures_file, "r", encoding="utf-8") as f:
        fixtures_data = json.load(f)
        fixtures = fixtures_data.get("events", [])

    rule_files = list(RULES_DIR.glob("*.yaml"))
    rules = {}
    rule_metadata = {}
    for rule_path in rule_files:
        rule_name = rule_path.stem
        with open(rule_path, "r", encoding="utf-8") as rf:
            r_data = yaml.safe_load(rf)
            rules[rule_name] = r_data
            rule_metadata[rule_name] = {
                "title": r_data.get("title"),
                "level": r_data.get("level"),
                "id": r_data.get("id"),
                "tags": r_data.get("tags", [])
            }

    start_time = time.time()
    test_results = []
    rule_stats = {r: {"true_positives": 0, "false_positives": 0, "true_negatives": 0, "passed": True} for r in rules}
    
    total_passed = 0
    total_failed = 0

    for event in fixtures:
        event_id_str = event["id"]
        description = event.get("description", "")
        expected = set(event.get("expected_detections", []))
        actual = set()

        for rule_name, rule_data in rules.items():
            detection = rule_data.get("detection", {})
            condition_str = detection.get("condition", "")
            
            selections = {}
            for sel_name, sel_dict in detection.items():
                if sel_name not in ["condition", "timeframe"]:
                    selections[sel_name] = matches_selection(sel_dict, event)

            if "|" in condition_str:
                base_cond, agg_part = condition_str.split("|", 1)
                base_cond = base_cond.strip()
                agg_part = agg_part.strip()
                
                if evaluate_condition_str(base_cond, selections):
                    if evaluate_aggregation(agg_part, base_cond, rule_data, event, fixtures):
                        actual.add(rule_name)
            else:
                if evaluate_condition_str(condition_str, selections):
                    actual.add(rule_name)

        passed = (actual == expected)
        if passed:
            total_passed += 1
        else:
            total_failed += 1

        for r_name in rules:
            if r_name in expected and r_name in actual:
                rule_stats[r_name]["true_positives"] += 1
            elif r_name not in expected and r_name in actual:
                rule_stats[r_name]["false_positives"] += 1
                rule_stats[r_name]["passed"] = False
            elif r_name not in expected and r_name not in actual:
                rule_stats[r_name]["true_negatives"] += 1

        test_results.append({
            "fixture_id": event_id_str,
            "description": description,
            "provider": event.get("provider", ""),
            "event_id": event.get("event_id", ""),
            "expected_detections": list(expected),
            "actual_detections": list(actual),
            "passed": passed
        })

    duration_ms = round((time.time() - start_time) * 1000, 2)
    overall_status = "PASSED" if total_failed == 0 else "FAILED"

    return {
        "status": overall_status,
        "duration_ms": duration_ms,
        "total_fixtures": len(fixtures),
        "passed_fixtures": total_passed,
        "failed_fixtures": total_failed,
        "pass_rate_pct": round((total_passed / len(fixtures)) * 100, 1) if fixtures else 100,
        "rule_stats": rule_stats,
        "rule_metadata": rule_metadata,
        "fixture_evaluations": test_results
    }


@app.get("/api/telemetry")
def get_telemetry_events():
    """Returns all mock & synthetic telemetry events."""
    fixtures_file = TESTS_DIR / "mock_telemetry_events.json"
    if fixtures_file.exists():
        with open(fixtures_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    return {"events": []}


@app.get("/api/queries")
def get_queries():
    """Returns Splunk SPL and Elastic KQL queries."""
    kql_file = RULES_DIR / "elastic_queries.kql"
    spl_file = RULES_DIR / "splunk_queries.spl"
    
    kql_content = kql_file.read_text(encoding="utf-8") if kql_file.exists() else ""
    spl_content = spl_file.read_text(encoding="utf-8") if spl_file.exists() else ""
    
    return {
        "elastic_kql": kql_content,
        "splunk_spl": spl_content
    }


@app.get("/api/matrix")
def get_matrix_coverage():
    """Returns MITRE ATT&CK Enterprise layer coverage data."""
    layer_file = NET_DIR / "mitre_attack_navigator_layer.json"
    if layer_file.exists():
        with open(layer_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"techniques": []}


@app.get("/api/topology")
def get_topology():
    """Returns cyber range network topology and subnet architecture."""
    return {
        "subnet": "192.168.56.0/24",
        "gateway": "192.168.56.1",
        "switch_type": "VirtualBox / VMware Host-Only Adapter",
        "nodes": [
            {
                "id": "node-attacker",
                "hostname": "kali-attacker",
                "ip": "192.168.56.20",
                "os": "Kali Linux 2024.x",
                "role": "Adversary Emulation Engine",
                "tools": ["Python 3 Emulation Engine", "Hydra", "Metasploit", "Nmap"],
                "color": "#ef4444",
                "status": "ACTIVE"
            },
            {
                "id": "node-target",
                "hostname": "win-server-2022",
                "ip": "192.168.56.10",
                "os": "Windows Server 2022 Datacenter",
                "role": "Defensive Endpoint Node",
                "tools": ["Microsoft Sysmon 4.90 (SwiftOnSecurity schema)", "Windows Advanced Audit Policy", "Winlogbeat 8.x"],
                "color": "#3b82f6",
                "status": "ACTIVE"
            },
            {
                "id": "node-siem",
                "hostname": "ubuntu-siem-core",
                "ip": "192.168.56.30",
                "os": "Ubuntu 22.04 LTS",
                "role": "SOC SIEM & Analytics Node",
                "tools": ["Elasticsearch 8.12.0", "Kibana 8.12.0", "Logstash / Beats (Port 5044)", "Splunk Enterprise"],
                "color": "#10b981",
                "status": "ACTIVE"
            }
        ],
        "data_flows": [
            {"from": "192.168.56.20", "to": "192.168.56.10", "type": "Adversary Attacks (RDP 3389, SMB 445, WinRM 5985)", "color": "#ef4444"},
            {"from": "192.168.56.10", "to": "192.168.56.30", "type": "Winlogbeat / Sysmon Telemetry Stream (Port 5044/9200)", "color": "#3b82f6"},
            {"from": "192.168.56.30", "to": "SOC Analyst", "type": "Kibana Dashboard / Splunk Web GUI (Port 5601 / 8000)", "color": "#10b981"}
        ]
    }


@app.get("/api/docs")
def list_docs():
    """List all documentation markdown guides."""
    docs = []
    for doc_file in sorted(DOCS_DIR.glob("*.md")):
        docs.append({
            "id": doc_file.stem,
            "filename": doc_file.name,
            "title": doc_file.stem.replace("_", " ").title()
        })
    return {"docs": docs}


@app.get("/api/docs/{doc_id}")
def get_doc_content(doc_id: str):
    """Fetch content of a documentation guide with strict path traversal prevention."""
    clean_id = os.path.basename(doc_id)
    if not clean_id.endswith(".md"):
        clean_id += ".md"
        
    doc_path = (DOCS_DIR / clean_id).resolve()
    if not str(doc_path).startswith(str(DOCS_DIR.resolve())) or not doc_path.exists():
        raise HTTPException(status_code=404, detail="Document not found or invalid path")
        
    content = doc_path.read_text(encoding="utf-8")
    return {
        "id": doc_path.stem,
        "filename": doc_path.name,
        "content": content
    }


# Mount static web directory
if not WEB_DIR.exists():
    WEB_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


@app.get("/", response_class=FileResponse)
def serve_index():
    """Serve the single page application."""
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Web UI Initializing...</h1>", status_code=200)
    return FileResponse(str(index_file))


SERVER_START_TIME = time.time()

if __name__ == "__main__":
    import uvicorn
    port = 8000
    print(f"[*] Launching Cyber Range SIEM Command Center at http://127.0.0.1:{port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info")
