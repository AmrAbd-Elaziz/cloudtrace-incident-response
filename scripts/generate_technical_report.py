#!/usr/bin/env python3

import argparse
import csv
import json
from collections import Counter
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
    "reports/technical/INCIDENT-ANALYSIS-REPORT.md"
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


def generate_report(
    timeline,
    findings,
    indicators,
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

    report = [
        "# CloudTrace Technical Incident Analysis",
        "",
        "## 1. Report Scope",
        "",
        (
            "This report documents the technical analysis of "
            "a synthetic AWS incident using CloudTrail evidence."
        ),
        "",
        (
            "> All identities, resources and indicators are "
            "synthetic and intended exclusively for authorized "
            "security training."
        ),
        "",
        "## 2. Evidence Summary",
        "",
        "| Evidence Metric | Result |",
        "|---|---:|",
        f"| Timeline events | {len(timeline)} |",
        f"| Detection findings | {len(findings)} |",
        f"| Critical findings | {severity_counts['Critical']} |",
        f"| High findings | {severity_counts['High']} |",
        f"| Medium findings | {severity_counts['Medium']} |",
        (
            "| Unique source IPs | "
            f"{len(indicators['source_ip_addresses'])} |"
        ),
        "",
        "## 3. Incident Timeline",
        "",
        (
            "| Seq | Time | Event | Actor | Source IP | "
            "Resource | Outcome | Severity |"
        ),
        "|---:|---|---|---|---|---|---|---|",
    ]

    for row in timeline:
        report.append(
            f"| {row['sequence']} "
            f"| {row['event_time']} "
            f"| `{row['event_name']}` "
            f"| `{row['actor']}` "
            f"| `{row['source_ip']}` "
            f"| {row['resource']} "
            f"| {row['outcome']} "
            f"| {row['severity']} |"
        )

    report.extend(
        [
            "",
            "## 4. Detection Findings",
            "",
            (
                "| ID | Finding | Severity | Event | "
                "Tactic | Technique | Outcome |"
            ),
            "|---|---|---|---|---|---|---|",
        ]
    )

    for finding in findings:
        report.append(
            f"| {finding['finding_id']} "
            f"| {finding['title']} "
            f"| {finding['severity']} "
            f"| `{finding['event_name']}` "
            f"| {finding['mitre_tactic']} "
            f"| {finding['mitre_technique']} "
            f"| {finding['outcome']} |"
        )

    report.extend(
        [
            "",
            "## 5. MITRE ATT&CK Coverage",
            "",
            "| Tactic | Findings |",
            "|---|---:|",
        ]
    )

    tactic_order = (
        "Discovery",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Collection",
    )

    for tactic in tactic_order:
        if tactic_counts[tactic]:
            report.append(
                f"| {tactic} | {tactic_counts[tactic]} |"
            )

    report.extend(
        [
            "",
            "## 6. Extracted Indicators",
            "",
            "| Indicator Type | Value |",
            "|---|---|",
            (
                "| Source IP | "
                + ", ".join(
                    f"`{value}`"
                    for value in indicators[
                        "source_ip_addresses"
                    ]
                )
                + " |"
            ),
            (
                "| Observed actors | "
                + ", ".join(
                    f"`{value}`"
                    for value in indicators["observed_actors"]
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
            "## 7. Attack-Sequence Analysis",
            "",
            "### Discovery",
            "",
            (
                "The actor validated the active identity and "
                "enumerated IAM users, S3 buckets and account "
                "authorization details."
            ),
            "",
            "### Persistence",
            "",
            (
                "The actor created `system-support-backup` and "
                "generated programmatic credentials for the "
                "new identity."
            ),
            "",
            "### Privilege Escalation",
            "",
            (
                "The AWS-managed `AdministratorAccess` policy "
                "was attached, establishing a highly privileged "
                "secondary access path."
            ),
            "",
            "### Defense Evasion",
            "",
            (
                "CloudTrail logging was successfully stopped. "
                "A later attempt to delete the trail failed."
            ),
            "",
            "### Collection",
            "",
            (
                "The actor inspected S3 configuration, "
                "enumerated objects and successfully accessed "
                "an object in `financial-transaction-archive`."
            ),
            "",
            "## 8. Detection Engineering Coverage",
            "",
            "| Sigma Rule | Target Activity |",
            "|---|---|",
            (
                "| `aws_iam_user_creation.yml` "
                "| Unauthorized cloud-account creation |"
            ),
            (
                "| `aws_administrator_policy_attachment.yml` "
                "| Administrative policy attachment |"
            ),
            (
                "| `aws_cloudtrail_logging_tampering.yml` "
                "| CloudTrail stop or deletion activity |"
            ),
            "",
            "The rules are validated against the synthetic "
            "CloudTrail dataset through automated tests.",
            "",
            "## 9. Technical Conclusions",
            "",
            (
                "- The activity represents a connected attack "
                "sequence rather than isolated administrative events."
            ),
            (
                "- Privileged persistence was successfully "
                "established."
            ),
            (
                "- CloudTrail visibility was successfully impaired."
            ),
            (
                "- S3 object access is confirmed by the evidence."
            ),
            (
                "- The original credential-acquisition method "
                "is not represented."
            ),
            (
                "- External data exfiltration is not independently "
                "confirmed."
            ),
            "",
            "## 10. Evidence References",
            "",
            "- `data/raw/cloudtrail-events.json`",
            "- `data/processed/incident-timeline.csv`",
            "- `data/processed/detection-findings.json`",
            "- `data/processed/indicators.json`",
            "- `docs/INVESTIGATION.md`",
            "- `docs/ROOT-CAUSE-ANALYSIS.md`",
            "- `docs/INCIDENT-RESPONSE-PLAN.md`",
            "",
        ]
    )

    return "\n".join(report)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate the CloudTrace technical report."
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
    print(f"Technical report: {args.output}")


if __name__ == "__main__":
    main()