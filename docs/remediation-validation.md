# Remediation and Validation

## Triage
1. Confirm source and destination asset identity and ownership.
2. Check approved change windows, deployment records, and service dependencies.
3. Determine whether the path, port, volume, and zone transition are expected.
4. Escalate high-risk administrative-protocol or segmentation anomalies for analyst review.

## Remediation
- Remove obsolete network paths and firewall rules.
- Restrict administrative protocols to approved management zones.
- Update segmentation policy where business-approved dependencies exist.
- Investigate unknown external destinations before allow-listing.

## Validation
Re-run the detector against post-change synthetic or approved telemetry. Close a finding only when the observed path matches documented network intent, the technical control is verified, and the baseline update is peer reviewed.
