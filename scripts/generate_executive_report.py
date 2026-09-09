#!/usr/bin/env python3

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


DEFAULT_TIMELINE = Path(
    "data/processed/incident-timeline.csv"
)
DEFAULT_FINDINGS = Path(
    "data/processed/detection-findings.json"
)
DEFAULT_INDICATORS = Path(
    "data/processed/indicators.json"
)
DEFAULT_OUTPUT = Path(
    "reports/executive/EXECUTIVE-INCIDENT-REPORT.md"
)


def load_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def load_timeline(path):
    with path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        return list(csv.DictReader(file))


def format_duration(start_time, end_time):
    start = datetime.fromisoformat(
        start_time.replace("Z", "+00:00")
    )
    end = datetime.fromisoformat(
        end_time.replace("Z", "+00:00")
    )

    total_seconds = int((end - start).total_seconds())
    minutes, seconds = divmod(total_seconds, 60)

    return f"{minutes} minutes {seconds} seconds"


def generate_report(
    timeline,
    findings,
    indicators,
    assessment_date,
):
    if not timeline:
        raise ValueError("Timeline cannot be empty")

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    successful_events = sum(
        row["outcome"] == "Success"
        for row in timeline
    )
    failed_events = sum(
        row["outcome"] == "Failed"
        for row in timeline
    )

    start_time = timeline[0]["event_time"]
    end_time = timeline[-1]["event_time"]
    duration = format_duration(start_time, end_time)

    critical_findings = [
        finding
        for finding in findings
        if finding["severity"] == "Critical"
    ]

    report = [
        "# Executive Cloud Incident Report",
        "",
        "## Assessment Overview",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Assessment date | {assessment_date} |",
        f"| CloudTrail events analyzed | {len(timeline)} |",
        f"| Detection findings | {len(findings)} |",
        f"| Critical findings | {severity_counts['Critical']} |",
        f"| High findings | {severity_counts['High']} |",
        f"| Medium findings | {severity_counts['Medium']} |",
        f"| Successful API operations | {successful_events} |",
        f"| Failed API operations | {failed_events} |",
        f"| Incident duration | {duration} |",
        "",
        "## Executive Summary",
        "",
        (
            "CloudTrace identified a simulated critical AWS "
            "security incident involving suspected misuse of "
            "the `backup-automation` IAM identity."
        ),
        "",
        (
            f"The activity contained {len(timeline)} CloudTrail "
            f"events and produced {len(findings)} security "
            "findings, including "
            f"{severity_counts['Critical']} Critical, "
            f"{severity_counts['High']} High and "
            f"{severity_counts['Medium']} Medium findings."
        ),
        "",
        (
            "The observed sequence included cloud-resource "
            "discovery, creation of a privileged IAM identity, "
            "generation of persistent credentials, disruption "
            "of CloudTrail logging and access to an S3 object."
        ),
        "",
        (
            "The available evidence confirms administrative "
            "changes and object access. It does not independently "
            "confirm how the original credentials were obtained "
            "or whether data was externally exfiltrated."
        ),
        "",
        "## Business Risk",
        "",
        "| Risk Area | Assessment |",
        "|---|---|",
        (
            "| Identity and access | Critical — unauthorized "
            "privileged persistence was established |"
        ),
        (
            "| Data confidentiality | High — a potentially "
            "sensitive S3 object was accessed |"
        ),
        (
            "| Auditability | Critical — CloudTrail logging "
            "was successfully stopped |"
        ),
        (
            "| Operational availability | No direct service "
            "outage was represented in the dataset |"
        ),
        "",
        "## Critical Findings",
        "",
        (
            "| Time | Finding | Event | Tactic | "
            "Outcome |"
        ),
        "|---|---|---|---|---|",
    ]

    for finding in critical_findings:
        report.append(
            f"| {finding['event_time']} "
            f"| {finding['title']} "
            f"| `{finding['event_name']}` "
            f"| {finding['mitre_tactic']} "
            f"| {finding['outcome']} |"
        )

    report.extend(
        [
            "",
            "## Incident Indicators",
            "",
            "| Indicator Type | Value |",
            "|---|---|",
            (
                "| Source IP addresses | "
                + ", ".join(
                    f"`{value}`"
                    for value in indicators[
                        "source_ip_addresses"
                    ]
                )
                + " |"
            ),
            (
                "| Created IAM users | "
                + ", ".join(
                    f"`{value}`"
                    for value in indicators["created_users"]
                )
                + " |"
            ),
            (
                "| Accessed S3 buckets | "
                + ", ".join(
                    f"`{value}`"
                    for value in indicators[
                        "accessed_s3_buckets"
                    ]
                )
                + " |"
            ),
            "",
            "## Immediate Management Actions",
            "",
            (
                "1. Disable and rotate credentials associated "
                "with the affected automation identity."
            ),
            (
                "2. Disable and remove the unauthorized "
                "`system-support-backup` IAM identity."
            ),
            (
                "3. Remove unauthorized administrative "
                "policy assignments."
            ),
            (
                "4. Restore CloudTrail logging and verify "
                "organization-wide coverage."
            ),
            (
                "5. Review access to the "
                "`financial-transaction-archive` bucket."
            ),
            (
                "6. Search all accounts and regions for "
                "related identities, credentials and activity."
            ),
            (
                "7. Replace broad automation permissions "
                "with a least-privilege IAM role."
            ),
            "",
            "## Management Conclusion",
            "",
            (
                "The incident demonstrates how excessive "
                "permissions assigned to a workload identity "
                "can expand credential misuse into privileged "
                "persistence, impaired visibility and access "
                "to cloud-hosted data."
            ),
            "",
            (
                "Secure closure requires verified credential "
                "rotation, removal of unauthorized persistence, "
                "restoration of logging, review of affected data "
                "and implementation of preventive IAM controls."
            ),
            "",
            (
                "> This report uses synthetic evidence and is "
                "intended exclusively for authorized security "
                "training and portfolio demonstration."
            ),
            "",
        ]
    )

    return "\n".join(report)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate the CloudTrace executive report."
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

    report = generate_report(
        timeline,
        findings,
        indicators,
        args.assessment_date,
    )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    args.output.write_text(
        report,
        encoding="utf-8",
    )

    print(f"Timeline events: {len(timeline)}")
    print(f"Detection findings: {len(findings)}")
    print(f"Executive report: {args.output}")


if __name__ == "__main__":
    main()