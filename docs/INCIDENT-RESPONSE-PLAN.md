# CloudTrace Incident Response Plan

## 1. Purpose

This plan defines the coordinated response to suspected compromise or misuse of AWS identities, unauthorized IAM changes, cloud-logging disruption and access to sensitive cloud resources.

It follows an evidence-driven lifecycle covering preparation, detection, analysis, containment, eradication, recovery and lessons learned.

> This portfolio project uses synthetic identities, infrastructure and evidence created exclusively for authorized security training.

## 2. Scope

The plan applies to incidents involving:

- AWS IAM users, roles and access keys
- AWS CloudTrail and security telemetry
- Amazon S3 buckets and objects
- Unauthorized privilege escalation
- Persistence through new cloud identities
- Suspicious API operations
- Potential exposure of cloud-hosted data

### Scenario in Scope

| Attribute | Value |
|---|---|
| Affected identity | `backup-automation` |
| Unauthorized identity | `system-support-backup` |
| Source IP | `198.51.100.24` |
| Target storage | `financial-transaction-archive` |
| Incident severity | Critical |
| Initial evidence source | AWS CloudTrail |
| Investigation period | 2026-09-09T08:00:12Z to 2026-09-09T08:16:55Z |

## 3. Response Objectives

The response team must:

1. Stop unauthorized cloud activity.
2. Preserve evidence before making unnecessary changes.
3. Remove unauthorized identities and credentials.
4. Restore security logging and visibility.
5. Determine the affected identities, resources and data.
6. Recover services using verified secure configurations.
7. Validate that persistence and excessive access have been removed.
8. Document decisions, evidence and residual risk.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Incident Commander | Coordinates response, priorities and communications |
| Cloud Security | Investigates AWS activity and implements containment |
| IAM Team | Disables credentials and corrects permissions |
| SOC / Detection Engineering | Reviews telemetry and expands detection coverage |
| Data Owner | Assesses sensitivity and business impact of accessed data |
| Legal / Privacy | Evaluates notification and regulatory obligations |
| Risk Owner | Reviews residual risk and approves documented exceptions |
| Communications | Coordinates approved internal and external messaging |
| Evidence Custodian | Preserves evidence integrity and chain of custody |

A responder should not approve their own high-risk remediation or evidence-closure decision.

## 5. Severity Classification

The scenario is classified as **Critical** because it includes:

- Suspected misuse of a cloud identity
- Creation of persistent credentials
- Assignment of administrative privileges
- Successful disruption of CloudTrail logging
- Access to a potentially sensitive S3 object
- Attempted deletion of audit infrastructure

### Escalation Triggers

Immediate escalation is required when:

- Administrative privileges are created unexpectedly.
- CloudTrail is stopped, modified or deleted.
- Sensitive cloud data is accessed by an unauthorized identity.
- Multiple accounts or AWS regions may be affected.
- The incident creates legal, financial or regulatory exposure.
- Investigation visibility is incomplete or unreliable.

## 6. Preparation

Before an incident occurs, the organization should:

- Centralize CloudTrail logs in a protected security account.
- Enable CloudTrail across all required accounts and regions.
- Protect logs using encryption and retention controls.
- Use temporary role credentials for automation.
- Apply least privilege and permission boundaries.
- Restrict high-risk IAM and CloudTrail operations.
- Maintain tested incident-response access.
- Alert on IAM creation, policy changes and logging disruption.
- Maintain current contact and escalation information.
- Test evidence collection and account-containment procedures.

## 7. Detection and Analysis

### Initial Triage

Responders should establish:

- Who performed the activity
- Which credentials were used
- Where the activity originated
- Which API operations succeeded or failed
- Which identities and resources were modified
- Whether logging was interrupted
- Whether sensitive data was accessed
- Whether the activity exists in other accounts or regions

### Required Evidence

Preserve the following where available:

- CloudTrail management and data events
- IAM credential reports
- IAM policy and role configurations
- AWS Organizations and Service Control Policies
- S3 access and object-level events
- GuardDuty, Security Hub and SIEM alerts
- Identity-provider and authentication logs
- Network, endpoint and proxy telemetry
- Relevant configuration histories
- Incident-response actions and timestamps

### Evidence Principles

- Preserve original evidence before transformation.
- Record collection time, source and collector.
- Store evidence in a restricted and integrity-protected location.
- Analyze working copies rather than original evidence.
- Record time zones consistently in UTC.
- Separate confirmed evidence from assumptions.
- Calculate and retain cryptographic hashes where appropriate.

## 8. Containment

### Immediate Containment

1. Disable access keys associated with `backup-automation`.
2. Prevent further sessions from using the affected identity.
3. Disable credentials belonging to `system-support-backup`.
4. Detach unauthorized administrative policies.
5. Restore CloudTrail logging immediately.
6. Protect the trail from further modification.
7. Restrict access to the affected S3 bucket.
8. Preserve current policies and configurations as evidence.
9. Search all AWS regions for related activity.
10. Monitor for continued use of affected indicators.

### Short-Term Containment

- Replace the affected automation identity with a restricted temporary role.
- Apply explicit controls against unauthorized IAM administration.
- Block CloudTrail modification by workload identities.
- Review other identities with equivalent permissions.
- Increase monitoring around sensitive S3 resources.
- Implement temporary network or identity restrictions where justified.
- Confirm that production operations remain available after containment.

Containment actions must be documented with the operator, timestamp, justification and result.

## 9. Eradication

The response team should:

1. Remove the unauthorized `system-support-backup` identity.
2. Delete or deactivate its access keys.
3. Remove unauthorized policies and permission changes.
4. Rotate exposed or potentially exposed credentials.
5. Correct excessive permissions assigned to `backup-automation`.
6. Remove equivalent persistence mechanisms.
7. Review recent IAM changes for additional unauthorized identities.
8. Confirm that CloudTrail configuration is trusted.
9. Review automation code and credential-storage locations.
10. Address the control weaknesses documented in the root-cause analysis.

Credential rotation alone is insufficient if unauthorized policies, users or access paths remain.

## 10. Recovery

Recovery should begin only after containment and eradication are validated.

### Recovery Activities

- Restore automation using a least-privilege IAM role.
- Verify CloudTrail coverage across accounts and regions.
- Confirm logs are delivered to protected storage.
- Validate access controls on sensitive S3 resources.
- Test required business functions.
- Monitor restored services for recurring activity.
- Confirm that detection rules generate expected alerts.
- Obtain approval from the Incident Commander and service owner.

### Recovery Validation

| Validation | Required Result |
|---|---|
| Unauthorized user search | No unauthorized identities remain |
| Access-key review | Unapproved credentials disabled or removed |
| Effective permission review | Least privilege confirmed |
| CloudTrail verification | Logging active and protected |
| S3 access review | Authorized access only |
| Detection testing | High-risk activity generates alerts |
| Cross-region review | No related persistence identified |
| Evidence review | Response actions documented |

## 11. Communications

Communications must be accurate, approved and appropriate for the audience.

### Internal Updates Should Include

- Confirmed facts
- Current severity
- Affected identities and resources
- Containment status
- Business impact
- Known evidence gaps
- Decisions required
- Next update time

Responders must not describe initial credential theft or external data exfiltration as confirmed unless supported by evidence.

External or regulatory communication must be coordinated with authorized Legal, Privacy and Communications stakeholders.

## 12. Closure Criteria

The incident may be closed only when:

- Unauthorized activity has stopped.
- Affected credentials have been disabled or rotated.
- Unauthorized identities and permissions have been removed.
- CloudTrail logging has been restored and validated.
- Sensitive-resource access has been reviewed.
- Related activity has been searched across accounts and regions.
- Corrective controls have been implemented or formally tracked.
- Recovery testing has passed.
- Evidence and response decisions have been retained.
- Residual risks have accountable owners and target dates.
- The Incident Commander approves closure.

Ticket completion alone does not demonstrate secure closure.

## 13. Lessons Learned

A lessons-learned review should be completed after recovery to determine:

- Which control first detected the incident
- Which controls failed to prevent the activity
- Whether escalation occurred quickly enough
- Whether responders had sufficient access and evidence
- Whether containment caused operational impact
- Which detection and prevention controls require improvement
- Whether similar exposure exists elsewhere
- Which actions require long-term ownership

Improvement actions should include accountable owners, priorities, target dates and validation evidence.

## 14. Related Project Evidence

- `docs/INVESTIGATION.md`
- `docs/ROOT-CAUSE-ANALYSIS.md`
- `data/raw/cloudtrail-events.json`
- `data/processed/incident-timeline.csv`
- `data/processed/detection-findings.json`
- `data/processed/indicators.json`

## 15. Security Engineering Principle

> Effective incident response does not end when suspicious activity stops. Closure requires verified eradication, restored visibility, evidence-backed recovery and corrective controls that reduce recurrence.