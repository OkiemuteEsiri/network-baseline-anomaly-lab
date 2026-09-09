# Example Network Anomaly Findings

## Summary
Synthetic telemetry produced three notable deviations from the approved network baseline: an unapproved RDP port to a database host, a new workstation-to-database path, and a first-seen external destination from an application host.

| Rule | Severity | Observation | Action |
|---|---|---|---|
| NET-02 | High | RDP observed on app-to-db path | Confirm administrative need; otherwise block and investigate |
| NET-01 | Medium | New workstation-to-db communication | Validate ownership and segmentation intent |
| NET-05 | Medium | First-seen external destination | Confirm destination reputation and business purpose |
| NET-03 | Medium | Connection volume exceeds baseline | Review workload/change context and tune if approved |

This report is generated from synthetic documentation-only data and does not represent a real environment.
