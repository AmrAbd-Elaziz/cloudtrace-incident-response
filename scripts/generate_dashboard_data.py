#!/usr/bin/env python3

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import yaml


DEFAULT_TIMELINE = Path(
    "data/processed/incident-timeline.csv"
)
DEFAULT_FINDINGS = Path(
    "data/processed/detection-findings.json"
)
DEFAULT_INDICATORS = Path(
    "data/processed/indicators.json"
)
DEFAULT_RULES = Path("detections/sigma")
DEFAULT_OUTPUT = Path("dashboard/data.json")


def load_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def load_timeline(path):
    with path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        return list(csv.DictReader(file))


def load_sigma_rules(directory):
    rules = []

    for path in sorted(directory.glob("*.yml")):
        with path.open(encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        rules.append(
            {
                "file": path.name,
                "title": rule["title"],
                "level": rule["level"],
                "status": rule["status"],
                "tags": rule.get("tags", []),
            }
        )

    return rules


def calculate_duration(start_time, end_time):
    start = datetime.fromisoformat(
        start_time.replace("Z", "+00:00")
    )
    end = datetime.fromisoformat(
        end_time.replace("Z", "+00:00")
    )

    return int((end - start).total_seconds())


def build_dashboard_data(
    timeline,
    findings,
    indicators,
    sigma_rules,
    assessment_date,
):
    if not timeline:
        raise ValueError("Timeline cannot be empty")

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )
    tactic_counts = Counter(
        finding["mitre_tactic"]
        for finding in findings
    )

    successful_events = sum(
        event["outcome"] == "Success"
        for event in timeline
    )
    failed_events = sum(
        event["outcome"] == "Failed"
        for event in timeline
    )

    duration_seconds = calculate_duration(
        timeline[0]["event_time"],
        timeline[-1]["event_time"],
    )

    return {
        "project": "CloudTrace",
        "assessment_date": assessment_date,
        "incident": {
            "title": "Suspected AWS IAM Credential Misuse",
            "classification": "Critical",
            "affected_identity": "backup-automation",
            "created_identity": "system-support-backup",
            "target_resource": (
                "financial-transaction-archive"
            ),
            "start_time": timeline[0]["event_time"],
            "end_time": timeline[-1]["event_time"],
            "duration_seconds": duration_seconds,
        },
        "metrics": {
            "events_analyzed": len(timeline),
            "detection_findings": len(findings),
            "critical_findings": severity_counts["Critical"],
            "high_findings": severity_counts["High"],
            "medium_findings": severity_counts["Medium"],
            "successful_operations": successful_events,
            "failed_operations": failed_events,
            "sigma_rules": len(sigma_rules),
            "source_ip_indicators": len(
                indicators["source_ip_addresses"]
            ),
        },
        "severity_distribution": {
            severity: severity_counts.get(severity, 0)
            for severity in (
                "Critical",
                "High",
                "Medium",
                "Low",
            )
        },
        "mitre_tactics": {
            tactic: tactic_counts.get(tactic, 0)
            for tactic in (
                "Discovery",
                "Persistence",
                "Privilege Escalation",
                "Defense Evasion",
                "Collection",
            )
        },
        "indicators": indicators,
        "sigma_rules": sigma_rules,
        "timeline": timeline,
        "findings": findings,
    }


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate CloudTrace dashboard data."
    )

    parser.add_argument(
        "--timeline",
        type=Path,
        default=DEFAULT_TIMELINE,
    )
    parser.add_argument(
        "--findings",
        type=Path,
        default=DEFAULT_FINDINGS,
    )
    parser.add_argument(
        "--indicators",
        type=Path,
        default=DEFAULT_INDICATORS,
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )
    parser.add_argument(
        "--assessment-date",
        default="2026-09-09",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    timeline = load_timeline(args.timeline)
    findings = load_json(args.findings)
    indicators = load_json(args.indicators)
    sigma_rules = load_sigma_rules(args.rules)

    dashboard_data = build_dashboard_data(
        timeline,
        findings,
        indicators,
        sigma_rules,
        args.assessment_date,
    )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    args.output.write_text(
        json.dumps(
            dashboard_data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "Dashboard events: "
        f"{dashboard_data['metrics']['events_analyzed']}"
    )
    print(
        "Dashboard findings: "
        f"{dashboard_data['metrics']['detection_findings']}"
    )
    print(
        "Dashboard Sigma rules: "
        f"{dashboard_data['metrics']['sigma_rules']}"
    )
    print(f"Dashboard data: {args.output}")


if __name__ == "__main__":
    main()