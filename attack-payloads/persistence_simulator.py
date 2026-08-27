#!/usr/bin/env python3
"""
Adversary Emulation: Host Persistence via Registry Run Key & Scheduled Task
Framework: MITRE ATT&CK T1547.001 (Boot/Logon Autostart: Registry Run Keys) & T1053.005 (Scheduled Task)
Author: Nayan Solanki (Senior Detection Engineering Portfolio)
"""

import os
import platform
import subprocess
from typing import Any, Dict, Optional
try:
    from engine import BaseAdversaryTechnique
except ImportError:
    from .engine import BaseAdversaryTechnique


class PersistenceSimulator(BaseAdversaryTechnique):

    def __init__(self):
        super().__init__(
            technique_id="T1547.001",
            technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
            tactic="Persistence"
        )
        self.reg_key_name = "CyberRangeTestPersistence"
        self.task_name = "CyberRangeUpdateTask"

    def execute(self, target_ip: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        sim_details = {
            "reg_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "reg_value": "C:\\Windows\\System32\\cmd.exe /c echo cyber_range_persistence",
            "scheduled_task": self.task_name
        }

        if dry_run:
            return self.log_execution("DRY_RUN", sim_details)

        if platform.system().lower() == "windows":
            # 1. Simulate Registry Run Key Creation (Sysmon Event ID 12/13)
            cmd_reg = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{self.reg_key_name}" /t REG_SZ /d "{sim_details["reg_value"]}" /f'
            subprocess.run(cmd_reg, shell=True, capture_output=True, text=True)

            # 2. Simulate Scheduled Task Creation via schtasks (Event ID 4698 / Sysmon Event ID 1)
            cmd_task = f'schtasks /create /tn "{self.task_name}" /tr "notepad.exe" /sc ONLOGON /f'
            subprocess.run(cmd_task, shell=True, capture_output=True, text=True)

            sim_details["action"] = "Registry key and Scheduled Task injected successfully."
        else:
            sim_details["action"] = "Simulated injection on non-Windows host."

        return self.log_execution("SUCCESS", sim_details)

    def cleanup(self) -> bool:
        if platform.system().lower() == "windows":
            # Clean registry key
            subprocess.run(
                f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{self.reg_key_name}" /f',
                shell=True, capture_output=True, text=True
            )
            # Delete scheduled task
            subprocess.run(
                f'schtasks /delete /tn "{self.task_name}" /f',
                shell=True, capture_output=True, text=True
            )
            self.logger.info("Cleaned up persistence simulation artifacts.")
        return True


if __name__ == "__main__":
    sim = PersistenceSimulator()
    sim.execute()
    sim.cleanup()
