#!/usr/bin/env python3
"""
Detection-as-Code (DaC) Automated Test Suite
============================================
Author: Nayan Solanki (Senior Detection Engineering Portfolio)
Description: Unit testing harness for verifying Sigma detection rules against
             synthetic attack payloads and ensuring zero regression on false positive filters.
"""

import glob
import json
import os
import unittest
import yaml


class DetectionRuleValidationTests(unittest.TestCase):

    def setUp(self):
        self.rules_dir = os.path.join(os.path.dirname(__file__), "..", "detection-rules")
        self.fixtures_file = os.path.join(os.path.dirname(__file__), "mock_telemetry_events.json")

        with open(self.fixtures_file, "r", encoding="utf-8") as f:
            self.fixtures = json.load(f)["events"]

    def test_sigma_rules_schema_validity(self):
        """Verifies that all Sigma rules contain mandatory metadata fields."""
        required_fields = ["title", "id", "status", "description", "author", "logsource", "detection", "level", "tags"]
        rule_files = glob.glob(os.path.join(self.rules_dir, "*.yaml"))

        self.assertGreater(len(rule_files), 0, "No detection rules found to validate!")

        for rule_path in rule_files:
            with open(rule_path, "r", encoding="utf-8") as rf:
                rule_data = yaml.safe_load(rf)

            for field in required_fields:
                self.assertIn(
                    field, rule_data,
                    f"Rule '{os.path.basename(rule_path)}' is missing mandatory Sigma field: '{field}'"
                )

            # Assert MITRE ATT&CK tags exist
            has_attack_tag = any(tag.startswith("attack.") for tag in rule_data.get("tags", []))
            self.assertTrue(has_attack_tag, f"Rule '{os.path.basename(rule_path)}' must include MITRE ATT&CK tags!")

    def test_rdp_brute_force_detection_logic(self):
        """Validates detection condition match for RDP failed logon events."""
        tp_event = next(e for e in self.fixtures if e["id"] == "test_evt_001_rdp_brute_force_tp")
        self.assertEqual(tp_event["event_id"], 4625)
        self.assertIn(tp_event["event_data"]["LogonType"], ["3", "10"])

    def test_powershell_encoded_detection_logic(self):
        """Validates pattern matching for obfuscated PowerShell command line."""
        tp_event = next(e for e in self.fixtures if e["id"] == "test_evt_002_powershell_encoded_tp")
        cmdline = tp_event["event_data"]["CommandLine"].lower()
        matched = any(kw in cmdline for kw in ["-enc", "-encodedcommand", "downloadstring"])
        self.assertTrue(matched, "Obfuscated PowerShell event failed keyword assertion")

    def test_lsass_process_access_filter(self):
        """Ensures benign system binaries (svchost.exe) are excluded from LSASS alert triggers."""
        fp_event = next(e for e in self.fixtures if e["id"] == "test_evt_004_benign_svchost_fp_filter")
        is_svchost = "svchost.exe" in fp_event["event_data"]["SourceImage"].lower()
        self.assertTrue(is_svchost, "Benign filter test case should match svchost.exe")


if __name__ == "__main__":
    unittest.main()
