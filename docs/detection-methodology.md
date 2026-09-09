# Detection Methodology

This lab uses an explicit communication baseline rather than opaque anomaly scores. Each observed flow is evaluated against known source/destination pairs, approved ports, expected network-zone transitions, normal connection volume, and approved external destinations.

## Engineering principles
- Prefer explainable detections over black-box scoring.
- Enrich anomalies with asset criticality and change context before production use.
- Treat first-seen behavior as a triage signal, not proof of compromise.
- Tune administrative protocol detections more aggressively because they can indicate lateral movement or remote administration.
- Retain suppression decisions and approved exceptions as governed configuration.

## ATT&CK context
Remote Services (T1021) and Application Layer Protocol (T1071) are included as defensive analytical context. The detector does not generate malicious traffic or perform exploitation.
