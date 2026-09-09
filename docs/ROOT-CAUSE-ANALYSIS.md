# CloudTrace Root Cause Analysis

## 1. Purpose

This document analyzes the control failures that enabled the simulated AWS incident documented in the CloudTrace investigation.

The analysis separates confirmed CloudTrail evidence from reasonable security conclusions and unresolved questions.

> This project uses synthetic events, identities and infrastructure created exclusively for authorized security training.

## 2. Incident Statement

On September 9, 2026, the IAM identity `backup-automation` performed a sequence of unauthorized actions from `198.51.100.24`.

The activity included cloud discovery, creation of a privileged IAM user, generation of persistent credentials, disruption of CloudTrail logging and access to an object stored in the `financial-transaction-archive` S3 bucket.

## 3. Root-Cause Summary

The primary control failure was an automation identity with permissions broad enough to:

- Enumerate IAM and S3 resources
- Create new IAM users
- Generate access keys
- Attach administrative policies
- Stop CloudTrail logging
- Access sensitive S3 resources

Misuse of this identity therefore provided a direct path from initial credential access to administrative persistence and data access.

The dataset does not establish how the original `backup-automation` credentials were obtained. The initial credential-access mechanism remains undetermined.

## 4. Confirmed Evidence

| Evidence | Security Significance |
|---|---|
| All events used `backup-automation` | One identity performed the complete activity chain |
| All events originated from `198.51.100.24` | The activity had a consistent external source |
| `CreateUser` succeeded | A secondary IAM identity was established |
| `CreateAccessKey` succeeded | Persistent programmatic credentials were created |
| `AttachUserPolicy` succeeded | Administrative privileges were granted |
| `StopLogging` succeeded | Audit visibility was deliberately impaired |
| `GetObject` succeeded | An S3 object was accessed |
| `DeleteTrail` failed | A further attempt to disrupt audit logging was blocked |

## 5. Primary Root Cause

### Excessive IAM Permissions

The `backup-automation` identity was able to perform operations beyond the expected responsibilities of a backup service account.

A least-privilege policy should not normally allow a backup identity to:

- Create IAM users
- Create credentials for other identities
- Attach administrative policies
- Modify or disable CloudTrail
- Access unrelated sensitive storage

This excessive authorization significantly increased the impact of credential misuse.

## 6. Contributing Factors

### 6.1 Long-Lived Programmatic Credentials

The activity suggests use of programmatic AWS credentials associated with an IAM user.

Long-lived access keys increase exposure because they remain valid until explicitly rotated, disabled or deleted.

The dataset does not provide the credential age or storage location, so credential leakage cannot be confirmed.

### 6.2 Missing Preventive IAM Guardrails

The successful creation and privilege escalation of `system-support-backup` indicates that preventive controls did not block high-risk IAM changes.

Relevant guardrails could include:

- AWS Organizations Service Control Policies
- Permission boundaries
- Restrictions on administrative policy attachment
- Separation of IAM administration from workload identities

### 6.3 Insufficient Protection of Audit Logging

The successful `StopLogging` event demonstrates that the affected identity could interfere with security telemetry.

CloudTrail administration should be restricted to dedicated security roles and protected through organizational controls.

### 6.4 Inadequate Separation of Duties

The same identity could perform operational activity, administer IAM, disrupt logging and access data.

Separating these functions would reduce the likelihood that compromise of one identity could affect multiple security layers.

### 6.5 Delayed Behavioral Detection

The sequence contained multiple high-confidence warning signs:

- Resource enumeration
- IAM user creation
- Access-key creation
- Administrative policy attachment
- CloudTrail disruption
- Sensitive S3 access

Near-real-time alerting should identify and interrupt this chain before it reaches data access.

## 7. Five-Whys Analysis

1. **Why was a sensitive S3 object accessed?**  
   Because the active identity had sufficient permissions to discover and retrieve it.

2. **Why could the actor establish privileged persistence?**  
   Because `backup-automation` could create users, create access keys and attach `AdministratorAccess`.

3. **Why could an automation identity perform administrative actions?**  
   Because its effective permissions exceeded its expected operational function.

4. **Why was the activity able to impair investigation visibility?**  
   Because the identity could stop CloudTrail logging without an effective preventive control.

5. **Why did the activity continue through multiple attack stages?**  
   Because least privilege, separation of duties, protected logging and rapid behavioral detection were not sufficiently enforced in the simulated environment.

## 8. Impact Assessment

| Impact Area | Assessment |
|---|---|
| Confidentiality | Potentially affected because an S3 object was accessed |
| Integrity | Affected through unauthorized IAM and policy changes |
| Availability | No direct service outage represented |
| Authentication | Affected through suspected credential misuse |
| Authorization | Critically affected through administrative privilege assignment |
| Auditability | Affected because CloudTrail logging was stopped |
| Persistence | Established through a new user and access key |

External data exfiltration is not confirmed by the available evidence.

## 9. Corrective Actions

| Priority | Corrective Action | Control Objective |
|---|---|---|
| P1 | Disable and rotate credentials for `backup-automation` | Contain credential misuse |
| P1 | Disable and remove `system-support-backup` | Eliminate unauthorized persistence |
| P1 | Remove unauthorized administrative policy assignments | Restore authorized access |
| P1 | Restore and verify CloudTrail logging | Recover audit visibility |
| P1 | Review access to `financial-transaction-archive` | Determine data exposure |
| P2 | Replace broad permissions with least-privilege policies | Reduce identity blast radius |
| P2 | Protect CloudTrail using organizational guardrails | Prevent logging disruption |
| P2 | Separate IAM, logging and data-access responsibilities | Enforce separation of duties |
| P2 | Alert on IAM users, access keys and policy changes | Detect persistence activity |
| P2 | Alert on CloudTrail modification or deletion attempts | Detect defense evasion |
| P3 | Prefer temporary role credentials over IAM access keys | Reduce credential exposure |
| P3 | Review unused identities and credentials regularly | Reduce attack surface |
| P3 | Add automated IAM-policy analysis to CI/CD | Prevent excessive permissions |

## 10. Detection Improvements

The following activity should generate immediate security alerts:

- IAM user creation by a non-administrative identity
- Access-key creation for another identity
- Attachment of `AdministratorAccess`
- CloudTrail `StopLogging`, `DeleteTrail` or configuration changes
- Sensitive S3 access following IAM privilege changes
- Operational service-account activity from an unusual external IP
- Multiple discovery operations followed by persistence activity

Individual alerts should be correlated into one incident when they share an identity, source IP and short time window.

## 11. Preventive Control Design

Recommended preventive controls include:

1. Use IAM roles with temporary credentials for automation.
2. Apply least-privilege policies scoped to required backup resources.
3. Deny IAM administration to workload identities.
4. Deny CloudTrail modification outside dedicated security roles.
5. Use Service Control Policies to protect organization-wide logging.
6. Apply permission boundaries to delegated IAM administration.
7. Require multi-party approval for high-risk access changes.
8. Centralize CloudTrail logs in a protected security account.
9. Enable immutable or retention-protected log storage.
10. Continuously review effective permissions and unused access.

## 12. Verification Criteria

Corrective actions should not be considered complete until:

- Unauthorized credentials are disabled.
- The persistence identity is removed.
- Excessive permissions are corrected.
- CloudTrail logging is operating across all required regions.
- Security logs are stored in a protected location.
- Sensitive S3 access is reviewed.
- New detection rules are tested successfully.
- Containment and remediation evidence is retained.
- No equivalent persistence or logging-control weakness remains.

## 13. Conclusion

The incident impact was enabled primarily by excessive permissions assigned to an automation identity, combined with insufficient separation of duties and inadequate protection of audit logging.

The initial credential-access method cannot be determined from the available evidence. The defensible conclusion is therefore credential misuse with an undetermined acquisition method—not confirmed credential theft.

Applying least privilege, temporary credentials, protected logging and correlated behavioral detection would materially reduce both the likelihood and impact of a similar incident.