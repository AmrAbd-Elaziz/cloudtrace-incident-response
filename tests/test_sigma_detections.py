import unittest
from pathlib import Path

from scripts.validate_detections import (
    load_events,
    load_rules,
    match_expected,
    rule_matches_event,
    validate_detections,
    validate_rule_structure,
)


EVENTS_PATH = Path("data/raw/cloudtrail-events.json")
RULES_DIRECTORY = Path("detections/sigma")


class SigmaStructureTests(unittest.TestCase):
    def test_three_sigma_rules_are_present(self):
        rules = load_rules(RULES_DIRECTORY)

        self.assertEqual(len(rules), 3)

    def test_all_rules_have_valid_structure(self):
        rules = load_rules(RULES_DIRECTORY)

        for path, rule in rules:
            validate_rule_structure(path, rule)

    def test_invalid_rule_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_rule_structure(
                Path("invalid-rule.yml"),
                {"title": "Incomplete rule"},
            )


class SigmaMatchingTests(unittest.TestCase):
    def setUp(self):
        self.events = load_events(EVENTS_PATH)
        self.rules = load_rules(RULES_DIRECTORY)

    def test_all_rules_match_demonstration_events(self):
        results = validate_detections(
            EVENTS_PATH,
            RULES_DIRECTORY,
        )

        self.assertEqual(len(results), 3)

        for result in results:
            self.assertGreater(result["matches"], 0)

    def test_cloudtrail_tampering_rule_matches_two_events(self):
        results = validate_detections(
            EVENTS_PATH,
            RULES_DIRECTORY,
        )

        tampering = next(
            result
            for result in results
            if result["rule"]
            == "aws_cloudtrail_logging_tampering.yml"
        )

        self.assertEqual(tampering["matches"], 2)
        self.assertEqual(
            set(tampering["events"]),
            {"StopLogging", "DeleteTrail"},
        )

    def test_administrator_policy_rule_matches_attachment(self):
        path, rule = next(
            item
            for item in self.rules
            if item[0].name
            == "aws_administrator_policy_attachment.yml"
        )

        matches = [
            event
            for event in self.events
            if rule_matches_event(rule, event)
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(
            matches[0]["eventName"],
            "AttachUserPolicy",
        )

    def test_endswith_operator(self):
        policy_arn = (
            "arn:aws:iam::aws:policy/AdministratorAccess"
        )

        self.assertTrue(
            match_expected(
                policy_arn,
                ":policy/AdministratorAccess",
                "endswith",
            )
        )

        self.assertFalse(
            match_expected(
                policy_arn,
                ":policy/ReadOnlyAccess",
                "endswith",
            )
        )


if __name__ == "__main__":
    unittest.main()