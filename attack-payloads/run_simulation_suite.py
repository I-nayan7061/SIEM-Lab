#!/usr/bin/env python3
"""
Full Kill-Chain Adversary Emulation Campaign Runner
===================================================
Author: Nayan Solanki (Senior Detection Engineering Portfolio)
Usage:
  python run_simulation_suite.py --target 192.168.56.10
  python run_simulation_suite.py --dry-run
"""

import argparse
import sys
from engine import AdversaryEmulationEngine
from persistence_simulator import PersistenceSimulator
from log_clearing_simulator import LogClearingSimulator
from brute_force_simulator import BruteForceSimulator
from credential_dump_simulator import CredentialDumpSimulator
from powershell_obfuscation import PowerShellSimulator


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Adversary Emulation & MITRE ATT&CK Simulation Campaign Suite"
    )
    parser.add_argument(
        "--target", "-t",
        default="192.168.56.10",
        help="Target IP of the Windows defensive node (Default: 192.168.56.10)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without modifying endpoint system state"
    )
    parser.add_argument(
        "--output", "-o",
        default="simulation_audit_report.json",
        help="Path for exporting structured execution metadata JSON report"
    )
    parser.add_argument(
        "--siem-url",
        help="Optional Elasticsearch URL to stream ground-truth execution logs (e.g. http://192.168.56.30:9200)"
    )

    args = parser.parse_args()

    engine = AdversaryEmulationEngine(output_report=args.output, siem_url=args.siem_url)

    # Register techniques
    engine.register_technique(BruteForceSimulator())
    engine.register_technique(PowerShellSimulator())
    engine.register_technique(CredentialDumpSimulator())
    engine.register_technique(PersistenceSimulator())
    engine.register_technique(LogClearingSimulator())

    # Execute campaign
    engine.run_all(target_ip=args.target, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
