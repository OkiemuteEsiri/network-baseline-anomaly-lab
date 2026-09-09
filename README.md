# Network Baseline Anomaly Lab

Defensive network-security and detection-engineering project for identifying meaningful deviations from an expected communication baseline using synthetic flow telemetry.

## Problem statement
Network teams often have large volumes of connection telemetry but limited context for deciding which changes matter. This lab models an explainable baseline and flags deviations such as new east-west paths, unusual destination ports, first-seen external destinations, volume spikes, and connections that cross expected segmentation boundaries.

## Architecture

```text
Synthetic flow telemetry + approved baseline
                |
                v
      src/anomaly_engine.py
        - baseline lookup
        - rule evaluation
        - risk scoring
                |
                +--> prioritized anomalies
                +--> analyst context
                +--> validation evidence
```

## Detection coverage
- First-seen source/destination communication pair.
- Unapproved destination port for a known pair.
- Connection-count spike relative to baseline.
- New external destination for a monitored asset.
- Unexpected network-zone transition.
- Administrative-protocol use outside the approved baseline.

## ATT&CK context
The project includes defensive context for **Remote Services (T1021)** and **Application Layer Protocol (T1071)** because anomalous network paths can be useful detection signals. It does not generate attack traffic or automate intrusion activity.

## Repository structure
- `src/anomaly_engine.py` — explainable rule-based detector.
- `data/baseline.json` — synthetic expected communication model.
- `data/flows.json` — synthetic observed flow telemetry.
- `tests/test_anomaly_engine.py` — unit tests.
- `docs/detection-methodology.md` — engineering approach and tuning guidance.
- `docs/remediation-validation.md` — response and revalidation workflow.
- `reports/example-findings.md` — analyst-facing example report.
- `.github/workflows/tests.yml` — CI tests.

## Usage
```bash
python -m unittest discover -s tests -v
python src/anomaly_engine.py data/baseline.json data/flows.json
```

## Risk classification
Critical/high scores are reserved for combinations of segmentation violations and administrative protocols. Medium findings typically indicate a meaningful baseline deviation requiring triage; low findings support tuning and inventory hygiene.

## Skills demonstrated
Network security monitoring, detection engineering, segmentation assurance, Python, synthetic telemetry design, unit testing, ATT&CK mapping, risk communication, remediation validation, and CI/CD.

## Limitations
This is an explainable lab detector, not an IDS replacement. It does not inspect payloads, capture production packets, scan networks, or infer compromise solely from anomaly presence. Production deployment would require asset identity, approved-change context, service ownership, suppression logic, and statistical tuning.

## Roadmap
- Add rolling time-window baselines.
- Add asset criticality and service ownership enrichment.
- Add allow-listed change windows.
- Add Sigma-style detection documentation and JSON output schema.
