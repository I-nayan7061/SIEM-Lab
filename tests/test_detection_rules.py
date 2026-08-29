#!/usr/bin/env python3
"""
Detection-as-Code (DaC) Automated Test Suite
============================================
Author: Nayan Solanki (Senior Detection Engineering Portfolio)
Description: Unit testing harness for dynamically verifying Sigma detection rules against
             synthetic attack payloads and ensuring zero regression on false positive filters.
"""

import glob
import json
import os
import re
import unittest
import yaml


def get_event_field(event, field_name):
    # Normalize comparison target by lowering and stripping underscores
    target = field_name.lower().replace("_", "")
    
    # Check event root
    for k, v in event.items():
        if k.lower().replace("_", "") == target:
            return v
    # Check event_data
    event_data = event.get("event_data", {})
    for k, v in event_data.items():
        if k.lower().replace("_", "") == target:
            return v
    return None


def match_value(event_val, rule_val, modifier):
    if isinstance(rule_val, list):
        return any(match_value(event_val, val, modifier) for val in rule_val)
    
    if event_val is None:
        return False
        
    event_str = str(event_val).lower()
    rule_str = str(rule_val).lower()
    
    if modifier == "endswith":
        return event_str.endswith(rule_str)
    elif modifier == "startswith":
        return event_str.startswith(rule_str)
    elif modifier == "contains":
        return rule_str in event_str
    elif modifier is None:
        return event_str == rule_str
        
    return False


def matches_selection(selection_dict, event):
    # A selection dict contains field matches.
    # All fields in selection_dict must match (AND logic).
    for key, rule_val in selection_dict.items():
        if "|" in key:
            field_name, modifier = key.split("|", 1)
        else:
            field_name, modifier = key, None
            
        event_val = get_event_field(event, field_name)
        if not match_value(event_val, rule_val, modifier):
            return False
            
    return True


def evaluate_condition_str(condition_str, selections):
    if "|" in condition_str:
        condition_str = condition_str.split("|")[0].strip()
        
    tokens = condition_str.split()
    new_tokens = []
    for token in tokens:
        token_lower = token.lower()
        if token_lower in ["and", "or", "not", "(", ")"]:
            new_tokens.append(token_lower)
        elif token in selections:
            new_tokens.append(str(selections[token]))
        else:
            # Clean up parenthesis
            clean_token = token.replace("(", "").replace(")", "")
            if clean_token in selections:
                replaced = token.replace(clean_token, str(selections[clean_token]))
                # Replace with lowercase booleans for python eval
                replaced_py = replaced.replace(str(selections[clean_token]), str(selections[clean_token]).lower())
                new_tokens.append(replaced_py)
            else:
                new_tokens.append(token)
                
    expr = " ".join(new_tokens)
    # Ensure lower case for true/false for python eval
    expr = expr.replace("True", "True").replace("False", "False").replace("true", "True").replace("false", "False")
    try:
        return bool(eval(expr, {"__builtins__": None}, {}))
    except Exception as e:
        print(f"Error evaluating condition expression '{expr}' from '{condition_str}': {e}")
        return False


def evaluate_aggregation(agg_part, base_cond, rule_data, current_event, all_events):
    # e.g., agg_part = "count(EventID) by IpAddress > 4"
    match = re.search(r"count\((.*?)\)\s+by\s+(\w+)\s*([><=]+)\s*(\d+)", agg_part)
    if not match:
        return False
        
    count_field, groupby_field, operator, threshold_str = match.groups()
    threshold = int(threshold_str)
    
    groupby_val = get_event_field(current_event, groupby_field)
    if groupby_val is None:
        return False
        
    matching_events_count = 0
    for event in all_events:
        # Check group value
        ev_val = get_event_field(event, groupby_field)
        if str(ev_val).lower() != str(groupby_val).lower():
            continue
            
        # Check base selection
        selections = {}
        for sel_name, sel_dict in rule_data["detection"].items():
            if sel_name not in ["condition", "timeframe"]:
                selections[sel_name] = matches_selection(sel_dict, event)
                
        if evaluate_condition_str(base_cond, selections):
            matching_events_count += 1
            
    if operator == ">":
        return matching_events_count > threshold
    elif operator == ">=":
        return matching_events_count >= threshold
    elif operator == "<":
        return matching_events_count < threshold
    elif operator == "<=":
        return matching_events_count <= threshold
    elif operator == "==":
        return matching_events_count == threshold
        
    return False


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

    def test_dynamic_sigma_detection_engine(self):
        """Dynamically evaluates all Sigma rules against all mock telemetry fixtures using the parser engine."""
        rule_files = glob.glob(os.path.join(self.rules_dir, "*.yaml"))
        self.assertGreater(len(rule_files), 0, "No Sigma rules found for dynamic execution!")
        
        # Load and parse all rules
        rules = {}
        for rule_path in rule_files:
            rule_name = os.path.splitext(os.path.basename(rule_path))[0]
            with open(rule_path, "r", encoding="utf-8") as rf:
                rules[rule_name] = yaml.safe_load(rf)

        # Run each rule against each event and check correctness
        errors = []
        for event in self.fixtures:
            event_id_str = event["id"]
            expected = set(event.get("expected_detections", []))
            actual = set()
            
            for rule_name, rule_data in rules.items():
                detection = rule_data.get("detection", {})
                condition_str = detection.get("condition", "")
                
                # Evaluate individual selections
                selections = {}
                for sel_name, sel_dict in detection.items():
                    if sel_name not in ["condition", "timeframe"]:
                        selections[sel_name] = matches_selection(sel_dict, event)
                
                # Evaluate full condition
                if "|" in condition_str:
                    base_cond, agg_part = condition_str.split("|", 1)
                    base_cond = base_cond.strip()
                    agg_part = agg_part.strip()
                    
                    base_match = evaluate_condition_str(base_cond, selections)
                    if base_match:
                        triggered = evaluate_aggregation(agg_part, base_cond, rule_data, event, self.fixtures)
                    else:
                        triggered = False
                else:
                    triggered = evaluate_condition_str(condition_str, selections)
                    
                if triggered:
                    actual.add(rule_name)
            
            # Assert match
            if actual != expected:
                errors.append(
                    f"Telemetry Event '{event_id_str}':\n"
                    f"  Expected detections: {list(expected)}\n"
                    f"  Actual detections:   {list(actual)}\n"
                    f"  Difference (False Positives/Negatives): {list(actual.symmetric_difference(expected))}"
                )
                
        self.assertEqual(len(errors), 0, "\n" + "\n\n".join(errors))


if __name__ == "__main__":
    unittest.main()
