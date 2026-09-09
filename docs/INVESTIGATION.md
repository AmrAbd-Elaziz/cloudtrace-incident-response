# CloudTrace Incident Investigation

## 1. Executive Summary

CloudTrace analyzed 12 synthetic AWS CloudTrail events associated with the IAM identity `backup-automation`.

The activity originated from the single external IP address `198.51.100.24` and occurred between `2026-09-09T08:00:12Z` and `2026-09-09T08:16:55Z`.

The observed sequence included:

- Identity and cloud-resource discovery
- Creation of a new IAM user
- Creation of persistent access credentials
- Assignment of administrative privileges
- Successful disruption of CloudTrail logging
- Discovery and access of an S3 object
- A failed attempt to delete the CloudTrail trail

The incident is classified as **Critical** because the activity established privileged persistence, impaired security visibility and accessed a potentially sensitive cloud object.

> All identities, resources, IP addresses and evidence in this project are synthetic and intended exclusively for authorized security training.

## 2. Investigation Scope

The investigation evaluates the following evidence:

- Raw AWS CloudTrail events
- Event timestamps and API operations
- Source IP addresses
- IAM identities and affected resources
- Successful and failed API activity
- MITRE ATT&CK tactics and techniques
- Automatically generated incident findings and timeline

### Evidence Files

| Evidence | Location |
|---|---|
| Raw CloudTrail events | `data/raw/cloudtrail-events.json` |
| Processed incident timeline | `data/processed/incident-timeline.csv` |
| Detection findings | `data/processed/detection-findings.json` |
| Extracted indicators | `data/processed/indicators.json` |

## 3. Incident Classification

| Attribute | Assessment |
|---|---|
| Incident title | Suspected AWS IAM credential compromise |
| Severity | Critical |
| Cloud environment | Synthetic AWS account |
| Affected identity | `backup-automation` |
| Source IP | `198.51.100.24` |
| Events analyzed | 12 |
| Detection findings | 11 |
| Critical findings | 6 |
| High findings | 2 |
| Medium findings | 3 |
| Failed API calls | 1 |
| Investigation status | Confirmed unauthorized activity in the simulation |

## 4. Investigation Timeline

| Sequence | Activity | Event | Interpretation |
|---:|---|---|---|
| 1 | Identity validation | `GetCallerIdentity` | The active AWS identity was confirmed before further activity. |
| 2 | IAM discovery | `ListUsers` | Existing cloud users were enumerated. |
| 3 | Storage discovery | `ListBuckets` | Available S3 buckets were enumerated. |
| 4 | Permission discovery | `GetAccountAuthorizationDetails` | IAM authorization details were reviewed. |
| 5 | Persistence | `CreateUser` | A new IAM user named `system-support-backup` was created. |
| 6 | Credential creation | `CreateAccessKey` | Programmatic credentials were created for the new user. |
| 7 | Privilege escalation | `AttachUserPolicy` | `AdministratorAccess` was attached to the created user. |
| 8 | Defense evasion | `StopLogging` | CloudTrail logging was successfully stopped. |
| 9 | Storage inspection | `GetBucketEncryption` | The encryption state of an S3 bucket was inspected. |
| 10 | Object discovery | `ListObjects` | Objects inside the target S3 bucket were enumerated. |
| 11 | Data access | `GetObject` | An object in `financial-transaction-archive` was accessed. |
| 12 | Defense evasion | `DeleteTrail` | An attempt to delete the CloudTrail trail failed. |

## 5. Key Findings

### 5.1 Suspicious Use of an Existing IAM Identity

All analyzed events originated from `198.51.100.24` and used the `backup-automation` IAM identity.

The activity pattern is inconsistent with a narrowly scoped backup function because it included IAM enumeration, user creation, privilege changes, logging disruption and access to cloud storage.

The available evidence supports suspected credential misuse. It does not identify how the original credentials were obtained.

### 5.2 Privileged Persistence Established

The activity created the IAM user `system-support-backup`, generated an access key and attached the AWS-managed `AdministratorAccess` policy.

This combination created a second privileged access path that could remain usable even if the original `backup-automation` credentials were disabled.

### 5.3 Security Logging Impaired

The `StopLogging` operation succeeded, reducing CloudTrail visibility during the incident.

A later `DeleteTrail` request failed. The failed deletion does not reduce the significance of the earlier successful logging disruption.

### 5.4 Sensitive Cloud Storage Accessed

The sequence `GetBucketEncryption`, `ListObjects` and `GetObject` shows deliberate inspection and access of the `financial-transaction-archive` bucket.

The `GetObject` event confirms access to a cloud object. CloudTrail management and data-event evidence alone does not prove that the data was transferred to an external destination or subsequently misused.

## 6. MITRE ATT&CK Mapping

| Observed Activity | Tactic | Technique |
|---|---|---|
| IAM user enumeration | Discovery | T1087.004 — Cloud Account |
| S3 bucket and object enumeration | Discovery | T1619 — Cloud Storage Object Discovery |
| Creation of a new IAM user | Persistence | T1136.003 — Cloud Account |
| Creation of additional access credentials | Persistence | T1098.001 — Additional Cloud Credentials |
| Attachment of administrative privileges | Privilege Escalation | T1098 — Account Manipulation |
| CloudTrail logging disruption | Defense Evasion | T1562.008 — Disable Cloud Logs |
| S3 object access | Collection | T1530 — Data from Cloud Storage |

## 7. Indicators and Affected Entities

| Type | Value | Assessment |
|---|---|---|
| Source IP | `198.51.100.24` | Synthetic external source using TEST-NET address space |
| Original identity | `backup-automation` | Suspected compromised IAM identity |
| Created identity | `system-support-backup` | Unauthorized persistence account |
| Attached policy | `AdministratorAccess` | Privileged access assigned |
| Target bucket | `financial-transaction-archive` | Potentially sensitive storage resource |
| Logging control | AWS CloudTrail | Successfully stopped during the incident |

## 8. Working Hypothesis

The most likely explanation is simulated compromise or misuse of credentials belonging to `backup-automation`.

The actor validated the credentials, performed discovery, established a privileged secondary identity, interfered with logging and accessed an S3 object.

The method used to obtain the original credentials is not present in the available dataset and must remain classified as **undetermined**.

## 9. Recommended Containment Actions

1. Disable access keys associated with `backup-automation`.
2. Disable and investigate `system-support-backup`.
3. Remove the attached `AdministratorAccess` policy.
4. Restore CloudTrail logging and verify trail integrity.
5. Review IAM, S3 and CloudTrail activity across all AWS regions.
6. Restrict access from the observed source IP where operationally appropriate.
7. Review the target S3 object and surrounding data events.
8. Preserve CloudTrail, IAM, S3 and authentication evidence.
9. Rotate any credentials accessible to the affected identities.
10. Search for similar persistence mechanisms across the account.

## 10. Investigation Limitations

- The dataset is synthetic and contains only the events required for this scenario.
- The original credential-access method is not represented.
- Host, network, identity-provider and endpoint telemetry is unavailable.
- Object access is confirmed, but external exfiltration is not independently proven.
- The dataset does not establish activity outside the documented time window.

## 11. Conclusion

The evidence demonstrates a simulated critical AWS security incident involving IAM credential misuse, discovery, privileged persistence, defense evasion and access to cloud-hosted data.

The investigation preserves the distinction between confirmed evidence and analytical inference: unauthorized administrative activity and object access are represented in the dataset, while initial credential theft and external data exfiltration remain unconfirmed.