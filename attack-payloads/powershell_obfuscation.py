#!/usr/bin/env python3
"""
Adversary Emulation: Encoded & Obfuscated PowerShell Execution
Framework: MITRE ATT&CK T1059.001 (PowerShell) & T1027 (Obfuscated Files/Info)
Author: Nayan Solanki
Purpose: Generates Base64 encoded and obfuscated PowerShell commands to trigger
         Windows Event ID 4104 (Script Block Logging) and Sysmon Event ID 1.
"""

import argparse
import base64
import subprocess
from engine import BaseAdversaryTechnique

TEST_PAYLOADS = [
    {
        "name": "System Discovery via Encoded Command",
        "raw_ps": "Get-WmiObject -Class Win32_ComputerSystem; Get-NetIPAddress",
        "description": "Enumerates host operating system details and network interfaces.",
        "use_raw": False
    },
    {
        "name": "Simulated In-Memory Web Cradle Download",
        "raw_ps": "$wc = New-Object System.Net.WebClient; # Simulated IEX download cradle",
        "description": "Simulates download cradle patterns commonly detected by SOCs.",
        "use_raw": False
    },
    {
        "name": "User Context & Privilege Query",
        "raw_ps": "whoami /priv; [System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
        "description": "Enumerates caller privilege tokens.",
        "use_raw": False
    },
    {
        "name": "Backtick Obfuscated Process Query (Raw)",
        "raw_ps": "powershell.exe -NoProfile -NonInteractive -Command \"G`e`t`-`P`r`o`c`e`s`s -N`a`m`e l`s`a`s`s\"",
        "description": "Uses backtick escape characters to obfuscate the cmdlet name directly on the command line.",
        "use_raw": True
    },
    {
        "name": "Format-String Obfuscated Invoke Expression (Raw)",
        "raw_ps": "powershell.exe -NoProfile -NonInteractive -Command \"& ( '{1}{0}' -f 'EX','I' ) ( '{1}{0}' -f 'host','write-' )\"",
        "description": "Reconstructs strings dynamically using format operators and invokes them.",
        "use_raw": True
    }
]

class PowerShellSimulator(BaseAdversaryTechnique):
    def __init__(self):
        super().__init__(
            technique_id="T1059.001",
            technique_name="Obfuscated PowerShell Execution",
            tactic="Execution"
        )

    def _encode_powershell(self, command: str) -> str:
        encoded_bytes = command.encode("utf-16le")
        return base64.b64encode(encoded_bytes).decode("ascii")

    def execute(self, target_ip=None, dry_run=False):
        results = []
        for idx, payload in enumerate(TEST_PAYLOADS, 1):
            name = payload["name"]
            raw = payload["raw_ps"]
            use_raw = payload.get("use_raw", False)
            
            if use_raw:
                cmd = raw
            else:
                b64 = self._encode_powershell(raw)
                cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {b64}"

            self.logger.info(f"[{idx}/{len(TEST_PAYLOADS)}] Vector: {name}")
            self.logger.info(f"    Command: {cmd}")
            
            if dry_run:
                self.logger.info("    [DRY RUN] Skipping actual execution.")
                results.append({"name": name, "executed": False})
                continue

            self.logger.info("    Executing command...")
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                self.logger.info(f"    Return Code: {res.returncode}")
                results.append({"name": name, "executed": True, "returncode": res.returncode})
            except Exception as e:
                self.logger.warning(f"    Execution encountered: {e}")
                results.append({"name": name, "executed": False, "error": str(e)})

        return {"payloads": results}

    def cleanup(self):
        return True


def main():
    parser = argparse.ArgumentParser(description="Simulate Obfuscated PowerShell")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    simulator = PowerShellSimulator()
    simulator.execute(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
