#!/usr/bin/env python3

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


DEFAULT_INPUT = Path("data/raw/cloudtrail-events.json")
DEFAULT_TIMELINE = Path("data/processed/incident-timeline.csv")
DEFAULT_FINDINGS = Path("data/processed/detection-findings.json")
DEFAULT_INDICATORS = Path("data/processed/indicators.json")


DETECTION_RULES = {
    "ListUsers": {
        "title": "IAM user enumeration",
        "severity": "Medium",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1087.004 - Cloud Account",
    },
    "ListBuckets": {
        "title": "S3 bucket enumeration",
        "severity": "Medium",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1619 - Cloud Storage Object Discovery",
    },
    "GetAccountAuthorizationDetails": {
        "title": "IAM authorization discovery",
        "severity": "High",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1087.004 - Cloud Account",
    },
    "CreateUser": {
        "title": "Unauthorized IAM user creation",
        "severity": "Critical",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.003 - Cloud Account",
    },
    "CreateAccessKey": {
        "title": "New cloud access key created",
        "severity": "Critical",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098.001 - Additional Cloud Credentials",
    },
    "AttachUserPolicy": {
        "title": "Privileged IAM policy attached",
        "severity": "Critical",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098 - Account Manipulation",
    },
    "StopLogging": {
        "title": "CloudTrail logging disabled",
        "severity": "Critical",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.008 - Disable Cloud Logs",
    },
    "GetBucketEncryption": {
        "title": "S3 encryption configuration discovery",
        "severity": "Medium",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1619 - Cloud Storage Object Discovery",
    },
    "ListObjects": {
        "title": "Sensitive bucket contents enumerated",
        "severity": "High",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1619 - Cloud Storage Object Discovery",
    },
    "GetObject": {
        "title": "Sensitive S3 object accessed",
        "severity": "Critical",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1530 - Data from Cloud Storage",
    },
    "DeleteTrail": {
        "title": "Attempted CloudTrail deletion",
        "severity": "Critical",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.008 - Disable Cloud Logs",
    },
}

def load_events(input_path):
    with input_path.open(encoding="utf-8") as file:
        report = json.load(file)

    events = report.get("Records")

    if not isinstance(events, list):
        raise ValueError("Input must contain a Records list")

    required_fields = {
        "eventTime",
        "eventSource",
        "eventName",
        "sourceIPAddress",
    }

    for row_number, event in enumerate(events, start=1):
        missing = [
            field
            for field in required_fields
            if not event.get(field)
        ]

        if missing:
            raise ValueError(
                f"Event {row_number}: missing required fields: "
                f"{', '.join(missing)}"
            )

    return sorted(
        events,
        key=lambda event: event["eventTime"],
    )


def get_actor(event):
    identity = event.get("userIdentity") or {}

    return (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("principalId")
        or identity.get("type")
        or "Unknown"
    )


def get_resource(event):
    parameters = event.get("requestParameters") or {}

    resource_fields = (
        "userName",
        "bucketName",
        "key",
        "trailName",
        "policyArn",
    )

    resources = []

    for field in resource_fields:
        value = parameters.get(field)

        if value:
            resources.append(f"{field}={value}")

    return "; ".join(resources) or "Not specified"


def build_timeline(events):
    timeline = []

    for sequence, event in enumerate(events, start=1):
        rule = DETECTION_RULES.get(event["eventName"], {})

        timeline.append(
            {
                "sequence": sequence,
                "event_time": event["eventTime"],
                "event_name": event["eventName"],
                "event_source": event["eventSource"],
                "actor": get_actor(event),
                "source_ip": event["sourceIPAddress"],
                "resource": get_resource(event),
                "outcome": (
                    "Failed"
                    if event.get("errorCode")
                    else "Success"
                ),
                "error_code": event.get("errorCode", ""),
                "severity": rule.get("severity", "Informational"),
                "mitre_tactic": rule.get(
                    "mitre_tactic",
                    "Not mapped",
                ),
                "mitre_technique": rule.get(
                    "mitre_technique",
                    "Not mapped",
                ),
            }
        )

    return timeline


def build_findings(events):
    findings = []

    for sequence, event in enumerate(events, start=1):
        rule = DETECTION_RULES.get(event["eventName"])

        if not rule:
            continue

        findings.append(
            {
                "finding_id": f"CT-{len(findings) + 1:03d}",
                "sequence": sequence,
                "event_time": event["eventTime"],
                "title": rule["title"],
                "severity": rule["severity"],
                "event_name": event["eventName"],
                "event_source": event["eventSource"],
                "actor": get_actor(event),
                "source_ip": event["sourceIPAddress"],
                "resource": get_resource(event),
                "outcome": (
                    "Failed"
                    if event.get("errorCode")
                    else "Success"
                ),
                "error_code": event.get("errorCode"),
                "mitre_tactic": rule["mitre_tactic"],
                "mitre_technique": rule["mitre_technique"],
            }
        )

    return findings


def build_indicators(events):
    source_ips = sorted(
        {
            event["sourceIPAddress"]
            for event in events
            if event.get("sourceIPAddress")
        }
    )

    actors = sorted(
        {
            get_actor(event)
            for event in events
            if get_actor(event) != "Unknown"
        }
    )

    created_users = set()
    accessed_buckets = set()

    for event in events:
        parameters = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "CreateUser"
            and parameters.get("userName")
        ):
            created_users.add(parameters["userName"])

        if parameters.get("bucketName"):
            accessed_buckets.add(parameters["bucketName"])

    return {
        "source_ip_addresses": source_ips,
        "observed_actors": actors,
        "created_users": sorted(created_users),
        "accessed_s3_buckets": sorted(accessed_buckets),
    }


def write_timeline(timeline, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "sequence",
        "event_time",
        "event_name",
        "event_source",
        "actor",
        "source_ip",
        "resource",
        "outcome",
        "error_code",
        "severity",
        "mitre_tactic",
        "mitre_technique",
    ]

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(timeline)


def write_json(data, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")


def analyze_incident(
    input_path,
    timeline_path,
    findings_path,
    indicators_path,
):
    events = load_events(input_path)
    timeline = build_timeline(events)
    findings = build_findings(events)
    indicators = build_indicators(events)

    write_timeline(timeline, timeline_path)
    write_json(findings, findings_path)
    write_json(indicators, indicators_path)

    return events, findings, indicators


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze synthetic AWS CloudTrail incident events."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
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

    return parser.parse_args()


def main():
    args = parse_arguments()

    events, findings, indicators = analyze_incident(
        args.input,
        args.timeline,
        args.findings,
        args.indicators,
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    print(f"CloudTrail events analyzed: {len(events)}")
    print(f"Detection findings: {len(findings)}")

    for severity in ("Critical", "High", "Medium", "Low"):
        print(
            f"{severity}: "
            f"{severity_counts.get(severity, 0)}"
        )

    print(
        "Source IP indicators: "
        f"{len(indicators['source_ip_addresses'])}"
    )
    print(f"Timeline: {args.timeline}")
    print(f"Findings: {args.findings}")
    print(f"Indicators: {args.indicators}")


if __name__ == "__main__":
    main()