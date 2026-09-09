import unittest
from pathlib import Path

from scripts.analyze_incident import (
    build_findings,
    build_indicators,
    build_timeline,
    get_actor,
    get_resource,
    load_events,
)


DATASET = Path("data/raw/cloudtrail-events.json")


class CloudTrailLoadingTests(unittest.TestCase):
    def test_dataset_contains_expected_events(self):
        events = load_events(DATASET)

        self.assertEqual(len(events), 12)

    def test_events_are_sorted_chronologically(self):
        events = load_events(DATASET)
        timestamps = [
            event["eventTime"]
            for event in events
        ]

        self.assertEqual(timestamps, sorted(timestamps))

    def test_expected_source_ip_is_present(self):
        events = load_events(DATASET)
        source_ips = {
            event["sourceIPAddress"]
            for event in events
        }

        self.assertEqual(source_ips, {"198.51.100.24"})


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = load_events(DATASET)
        self.findings = build_findings(self.events)

    def test_expected_number_of_findings(self):
        self.assertEqual(len(self.findings), 11)

    def test_critical_finding_count(self):
        critical = [
            finding
            for finding in self.findings
            if finding["severity"] == "Critical"
        ]

        self.assertEqual(len(critical), 6)

    def test_cloudtrail_defense_evasion_is_detected(self):
        event_names = {
            finding["event_name"]
            for finding in self.findings
        }

        self.assertIn("StopLogging", event_names)
        self.assertIn("DeleteTrail", event_names)

    def test_failed_delete_trail_is_recorded(self):
        finding = next(
            item
            for item in self.findings
            if item["event_name"] == "DeleteTrail"
        )

        self.assertEqual(finding["outcome"], "Failed")
        self.assertIsNotNone(finding["error_code"])

    def test_sensitive_s3_access_is_critical(self):
        finding = next(
            item
            for item in self.findings
            if item["event_name"] == "GetObject"
        )

        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["mitre_tactic"], "Collection")


class TimelineTests(unittest.TestCase):
    def test_timeline_includes_all_events(self):
        events = load_events(DATASET)
        timeline = build_timeline(events)

        self.assertEqual(len(timeline), 12)
        self.assertEqual(timeline[0]["sequence"], 1)
        self.assertEqual(timeline[-1]["sequence"], 12)

    def test_unmapped_event_is_informational(self):
        events = load_events(DATASET)
        timeline = build_timeline(events)

        first_event = timeline[0]

        self.assertEqual(
            first_event["event_name"],
            "GetCallerIdentity",
        )
        self.assertEqual(
            first_event["severity"],
            "Informational",
        )


class IndicatorTests(unittest.TestCase):
    def test_incident_indicators_are_extracted(self):
        events = load_events(DATASET)
        indicators = build_indicators(events)

        self.assertEqual(
            indicators["source_ip_addresses"],
            ["198.51.100.24"],
        )
        self.assertIn(
            "system-support-backup",
            indicators["created_users"],
        )
        self.assertIn(
            "financial-transaction-archive",
            indicators["accessed_s3_buckets"],
        )

    def test_null_request_parameters_are_safe(self):
        event = {
            "requestParameters": None,
        }

        self.assertEqual(
            get_resource(event),
            "Not specified",
        )

    def test_null_identity_is_safe(self):
        event = {
            "userIdentity": None,
        }

        self.assertEqual(
            get_actor(event),
            "Unknown",
        )


if __name__ == "__main__":
    unittest.main()