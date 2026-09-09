# CloudTrace Technical Incident Analysis

## 1. Report Scope

This report documents the technical analysis of a synthetic AWS incident using CloudTrail evidence.

> All identities, resources and indicators are synthetic and intended exclusively for authorized security training.

## 2. Evidence Summary

| Evidence Metric | Result |
|---|---:|
| Timeline events | 12 |
| Detection findings | 11 |
| Critical findings | 6 |
| High findings | 2 |
| Medium findings | 3 |
| Unique source IPs | 1 |

## 3. Incident Timeline

| Seq | Time | Event | Actor | Source IP | Resource | Outcome | Severity |
|---:|---|---|---|---|---|---|---|
| 1 | 2026-09-09T08:00:12Z | `GetCallerIdentity` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | Not specified | Success | Informational |
| 2 | 2026-09-09T08:01:43Z | `ListUsers` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | Not specified | Success | Medium |
| 3 | 2026-09-09T08:02:10Z | `ListBuckets` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | Not specified | Success | Medium |
| 4 | 2026-09-09T08:03:25Z | `GetAccountAuthorizationDetails` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | Not specified | Success | High |
| 5 | 2026-09-09T08:05:11Z | `CreateUser` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | userName=system-support-backup | Success | Critical |
| 6 | 2026-09-09T08:06:02Z | `CreateAccessKey` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | userName=system-support-backup | Success | Critical |
| 7 | 2026-09-09T08:07:34Z | `AttachUserPolicy` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | userName=system-support-backup; policyArn=arn:aws:iam::aws:policy/AdministratorAccess | Success | Critical |
| 8 | 2026-09-09T08:09:18Z | `StopLogging` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | Not specified | Success | Critical |
| 9 | 2026-09-09T08:11:09Z | `GetBucketEncryption` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | bucketName=financial-transaction-archive | Success | Medium |
| 10 | 2026-09-09T08:12:47Z | `ListObjects` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | bucketName=financial-transaction-archive | Success | High |
| 11 | 2026-09-09T08:14:31Z | `GetObject` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | bucketName=financial-transaction-archive; key=2026/Q3/transaction-export.csv | Success | Critical |
| 12 | 2026-09-09T08:16:55Z | `DeleteTrail` | `arn:aws:iam::111122223333:user/backup-automation` | `198.51.100.24` | Not specified | Failed | Critical |

## 4. Detection Findings

| ID | Finding | Severity | Event | Tactic | Technique | Outcome |
|---|---|---|---|---|---|---|
| CT-001 | IAM user enumeration | Medium | `ListUsers` | Discovery | T1087.004 - Cloud Account | Success |
| CT-002 | S3 bucket enumeration | Medium | `ListBuckets` | Discovery | T1619 - Cloud Storage Object Discovery | Success |
| CT-003 | IAM authorization discovery | High | `GetAccountAuthorizationDetails` | Discovery | T1087.004 - Cloud Account | Success |
| CT-004 | Unauthorized IAM user creation | Critical | `CreateUser` | Persistence | T1136.003 - Cloud Account | Success |
| CT-005 | New cloud access key created | Critical | `CreateAccessKey` | Persistence | T1098.001 - Additional Cloud Credentials | Success |
| CT-006 | Privileged IAM policy attached | Critical | `AttachUserPolicy` | Privilege Escalation | T1098 - Account Manipulation | Success |
| CT-007 | CloudTrail logging disabled | Critical | `StopLogging` | Defense Evasion | T1562.008 - Disable Cloud Logs | Success |
| CT-008 | S3 encryption configuration discovery | Medium | `GetBucketEncryption` | Discovery | T1619 - Cloud Storage Object Discovery | Success |
| CT-009 | Sensitive bucket contents enumerated | High | `ListObjects` | Discovery | T1619 - Cloud Storage Object Discovery | Success |
| CT-010 | Sensitive S3 object accessed | Critical | `GetObject` | Collection | T1530 - Data from Cloud Storage | Success |
| CT-011 | Attempted CloudTrail deletion | Critical | `DeleteTrail` | Defense Evasion | T1562.008 - Disable Cloud Logs | Failed |

## 5. MITRE ATT&CK Coverage

| Tactic | Findings |
|---|---:|
| Discovery | 5 |
| Persistence | 2 |
| Privilege Escalation | 1 |
| Defense Evasion | 2 |
| Collection | 1 |

## 6. Extracted Indicators

| Indicator Type | Value |
|---|---|
| Source IP | `198.51.100.24` |
| Observed actors | `arn:aws:iam::111122223333:user/backup-automation` |
| Created IAM users | `system-support-backup` |
| Accessed S3 buckets | `financial-transaction-archive` |

## 7. Attack-Sequence Analysis

### Discovery

The actor validated the active identity and enumerated IAM users, S3 buckets and account authorization details.

### Persistence

The actor created `system-support-backup` and generated programmatic credentials for the new identity.

### Privilege Escalation

The AWS-managed `AdministratorAccess` policy was attached, establishing a highly privileged secondary access path.

### Defense Evasion

CloudTrail logging was successfully stopped. A later attempt to delete the trail failed.

### Collection

The actor inspected S3 configuration, enumerated objects and successfully accessed an object in `financial-transaction-archive`.

## 8. Detection Engineering Coverage

| Sigma Rule | Target Activity |
|---|---|
| `aws_iam_user_creation.yml` | Unauthorized cloud-account creation |
| `aws_administrator_policy_attachment.yml` | Administrative policy attachment |
| `aws_cloudtrail_logging_tampering.yml` | CloudTrail stop or deletion activity |

The rules are validated against the synthetic CloudTrail dataset through automated tests.

## 9. Technical Conclusions

- The activity represents a connected attack sequence rather than isolated administrative events.
- Privileged persistence was successfully established.
- CloudTrail visibility was successfully impaired.
- S3 object access is confirmed by the evidence.
- The original credential-acquisition method is not represented.
- External data exfiltration is not independently confirmed.

## 10. Evidence References

- `data/raw/cloudtrail-events.json`
- `data/processed/incident-timeline.csv`
- `data/processed/detection-findings.json`
- `data/processed/indicators.json`
- `docs/INVESTIGATION.md`
- `docs/ROOT-CAUSE-ANALYSIS.md`
- `docs/INCIDENT-RESPONSE-PLAN.md`
