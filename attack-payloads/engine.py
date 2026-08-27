#!/usr/bin/env python3
"""
Enterprise Adversary Emulation Core Engine
==========================================
Author: Nayan Solanki (Senior Detection Engineering Portfolio)
Description: Modular, safe adversary simulation framework mapping directly to
             the MITRE ATT&CK matrix. Emits structured execution metadata,
             maintains safe rollback state, and supports dry-run / telemetry verification.
"""

import abc
import argparse
import datetime
import json
import logging
import os
import platform
import subprocess
import time
import urllib.request
from typing import Any, Dict, List, Optional

# Structured JSON Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)


class BaseAdversaryTechnique(abc.ABC):
    """Abstract base class for all MITRE ATT&CK adversary simulation modules."""

    def __init__(self, technique_id: str, technique_name: str, tactic: str):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.logger = logging.getLogger(f"Technique::{technique_id}")
        self.created_artifacts: List[str] = []

    @abc.abstractmethod
    def execute(self, target_ip: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        """Executes the adversary emulation routine and returns execution telemetry metadata."""
        pass

    @abc.abstractmethod
    def cleanup(self) -> bool:
        """Rolls back any modified state or transient artifacts generated during simulation."""
        pass

    def log_execution(self, status: str, details: Dict[str, Any]) -> Dict[str, Any]:
        record = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "status": status,
            "host_os": platform.system(),
            "details": details
        }
        self.logger.info(f"Execution telemetry record: {json.dumps(record, indent=2)}")
        return record


class AdversaryEmulationEngine:
    """Orchestrator for managing multi-stage simulation campaigns and generating audit logs."""

    def __init__(self, output_report: str = "simulation_run_report.json", siem_url: Optional[str] = None):
        self.registry: Dict[str, BaseAdversaryTechnique] = {}
        self.output_report = output_report
        self.siem_url = siem_url
        self.execution_history: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("AdversaryEngine")

    def register_technique(self, technique: BaseAdversaryTechnique) -> None:
        self.registry[technique.technique_id] = technique
        self.logger.info(f"Registered technique: [{technique.technique_id}] {technique.technique_name}")

    def run_all(self, target_ip: Optional[str] = None, dry_run: bool = False) -> None:
        self.logger.info("=" * 70)
        self.logger.info(f"STARTING ADVERSARY EMULATION CAMPAIGN (DryRun={dry_run})")
        self.logger.info("=" * 70)

        for tech_id, tech in self.registry.items():
            self.logger.info(f"\n>>> Executing [{tech_id}] {tech.technique_name} (Tactic: {tech.tactic})")
            start_time = time.time()
            try:
                result = tech.execute(target_ip=target_ip, dry_run=dry_run)
                result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
                self.execution_history.append(result)
            except Exception as ex:
                self.logger.error(f"Error executing {tech_id}: {ex}", exc_info=True)
                self.execution_history.append(tech.log_execution("FAILED", {"error": str(ex)}))
            finally:
                if not dry_run:
                    tech.cleanup()

        self._export_report()

    def _export_report(self) -> None:
        report = {
            "campaign_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "total_techniques_executed": len(self.execution_history),
            "results": self.execution_history
        }
        with open(self.output_report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        self.logger.info("=" * 70)
        self.logger.info(f"[✓] Campaign finished. Execution report exported to: {self.output_report}")
        
        if self.siem_url:
            self.logger.info(f"[>] Streaming Ground-Truth Telemetry to SIEM: {self.siem_url}")
            try:
                for idx, result in enumerate(self.execution_history):
                    req = urllib.request.Request(
                        f"{self.siem_url}/adversary-emulation/_doc/{idx}",
                        data=json.dumps(result).encode('utf-8'),
                        headers={'Content-Type': 'application/json'}
                    )
                    urllib.request.urlopen(req, timeout=3)
                self.logger.info(f"[+] Successfully pushed {len(self.execution_history)} records to Elasticsearch!")
            except Exception as e:
                self.logger.error(f"[-] Failed to stream telemetry to SIEM: {e}")
                
        self.logger.info("=" * 70)
