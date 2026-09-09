#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import yaml


DEFAULT_EVENTS = Path("data/raw/cloudtrail-events.json")
DEFAULT_RULES = Path("detections/sigma")

REQUIRED_RULE_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
}


def load_events(path):
    with path.open(encoding="utf-8") as file:
        report = json.load(file)

    events = report.get("Records")

    if not isinstance(events, list):
        raise ValueError("CloudTrail input must contain a Records list")

    return events


def load_rules(directory):
    rule_paths = sorted(directory.glob("*.yml"))

    if not rule_paths:
        raise ValueError(f"No Sigma rules found in {directory}")

    rules = []

    for path in rule_paths:
        with path.open(encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        if not isinstance(rule, dict):
            raise ValueError(f"{path}: rule must be a YAML mapping")

        rules.append((path, rule))

    return rules


def validate_rule_structure(path, rule):
    missing = sorted(REQUIRED_RULE_FIELDS - rule.keys())

    if missing:
        raise ValueError(
            f"{path}: missing required fields: {', '.join(missing)}"
        )

    logsource = rule["logsource"]

    if logsource.get("product") != "aws":
        raise ValueError(f"{path}: product must be aws")

    if logsource.get("service") != "cloudtrail":
        raise ValueError(f"{path}: service must be cloudtrail")

    detection = rule["detection"]

    if not isinstance(detection, dict):
        raise ValueError(f"{path}: detection must be a mapping")

    if not detection.get("condition"):
        raise ValueError(f"{path}: detection condition is required")


def get_nested_value(event, field):
    value = event

    for component in field.split("."):
        if not isinstance(value, dict):
            return None

        value = value.get(component)

    return value


def match_expected(actual, expected, operator=None):
    if isinstance(expected, list):
        return any(
            match_expected(actual, item, operator)
            for item in expected
        )

    if operator == "endswith":
        return (
            isinstance(actual, str)
            and actual.endswith(str(expected))
        )

    return actual == expected


def selection_matches(event, selection):
    if not isinstance(selection, dict):
        return False

    for expression, expected in selection.items():
        parts = expression.split("|", maxsplit=1)
        field = parts[0]
        operator = parts[1] if len(parts) == 2 else None

        actual = get_nested_value(event, field)

        if not match_expected(actual, expected, operator):
            return False

    return True


def rule_matches_event(rule, event):
    detection = rule["detection"]
    condition = detection["condition"].strip()

    selector_names = [
        part.strip()
        for part in condition.split(" and ")
    ]

    for selector_name in selector_names:
        selection = detection.get(selector_name)

        if selection is None:
            raise ValueError(
                f"{rule['title']}: unknown selector "
                f"{selector_name!r}"
            )

        if not selection_matches(event, selection):
            return False

    return True


def validate_detections(events_path, rules_directory):
    events = load_events(events_path)
    rules = load_rules(rules_directory)
    results = []

    for path, rule in rules:
        validate_rule_structure(path, rule)

        matches = [
            event
            for event in events
            if rule_matches_event(rule, event)
        ]

        if not matches:
            raise ValueError(
                f"{path}: rule does not match the demonstration dataset"
            )

        results.append(
            {
                "rule": path.name,
                "title": rule["title"],
                "level": rule["level"],
                "matches": len(matches),
                "events": [
                    event["eventName"]
                    for event in matches
                ],
            }
        )

    return results


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Validate Sigma rules and test them against "
            "synthetic CloudTrail events."
        )
    )

    parser.add_argument(
        "--events",
        type=Path,
        default=DEFAULT_EVENTS,
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES,
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    results = validate_detections(
        args.events,
        args.rules,
    )

    print("Sigma detection validation passed")
    print(f"Rules validated: {len(results)}")

    for result in results:
        event_names = ", ".join(result["events"])

        print(
            f"{result['rule']} | "
            f"{result['level']} | "
            f"{result['matches']} match(es) | "
            f"{event_names}"
        )


if __name__ == "__main__":
    main()