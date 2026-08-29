# services/detection

Behavioral baseline + anomaly detection (Python).

Learns each agent's normal tool-call sequences and flags deviations
(PRD §28) — e.g. `CRM.read → 50,000 records → Export → External API` scores as a
behavioral anomaly.

Also hosts threat detection that feeds Incident Response (PRD §30).

Implemented in **Step 8**. Runs off the event stream (async, off the critical
path).
