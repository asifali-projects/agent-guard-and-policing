# Risk Engine & DLP (Step 4)

Covers PRD §26 (risk factors) and §27 (data-loss prevention). Both run
**synchronously on the runtime critical path** and are deterministic.

## DLP — `agentguard_api/dlp/`

`detectors.py` is pure: regex + Luhn scanning of individual strings.
`service.scan_payload()` walks a payload, records the JSON path of every hit,
picks the highest classification, and resolves the action.

### Detectors

| Detector | Class | Detector | Class |
|---|---|---|---|
| `email` | confidential | `openai_key` | restricted |
| `phone` | confidential | `github_token` | restricted |
| `us_ssn` | restricted | `slack_token` | restricted |
| `credit_card` (Luhn-checked) | restricted | `gcp_api_key` | restricted |
| `iban` | restricted | `agentguard_key` | restricted |
| `jwt` | restricted | `private_key` | restricted |
| `aws_access_key` | restricted | `basic_auth` | restricted |
| `generic_secret` (key-name context) | restricted | | |

Samples in findings are **masked** (`jz****an`) — the raw value never leaves the
scanner.

### Classification → action

Classification is `PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED` (PRD §27).
The organization configures the action per classification via
`DataPolicy` rows; the most restrictive matching row wins
(`block > approval > redact > allow`). Built-in defaults when nothing is
configured:

| Classification | Default action |
|---|---|
| restricted | **block** |
| confidential | **redact** |
| internal / public | allow |

**`NEVER_EXFIL`** detectors (keys, tokens, private keys, `basic_auth`,
`generic_secret`) force `block` regardless of any `DataPolicy` — credentials
must never cross the boundary.

## Risk engine — `agentguard_api/risk/`

Seven factors (PRD §26), each scored 0–100, combined by weight:

| Factor | Weight | Derived from |
|---|---|---|
| identity | 0.15 | agent trust level + status |
| permission | 0.12 | highest permission scope on the tool |
| tool | 0.18 | `tool.risk` severity |
| data | 0.22 | DLP classification (+ NEVER_EXFIL → ≥96) |
| destination | 0.13 | `context.destination` (internal / external / unknown) |
| behavior | 0.10 | bulk-volume heuristic (**Step 8** replaces with real baselines) |
| historical | 0.10 | open high/critical findings + denies in the last 24 h |

```
risk_score = round(Σ factor.score × weight)     # 0–100
severity   = critical ≥85 · high ≥65 · medium ≥40 · low ≥20 · info
decision   = critical → BLOCK · high → APPROVAL · else ALLOW
```

## How they combine in the runtime (PRD §24–27)

```
scan payload (DLP)  ─┐
                     ├─►  candidate decisions  ─►  precedence  ─►  final
policy engine       ─┤        deny > approval > rate_limit > redact > allow
risk engine         ─┘
```

- DLP `block` or risk `BLOCK` → **DENY**.
- DLP `approval` or risk `APPROVAL` → **APPROVAL** (unless already denied).
- DLP `redact` → **REDACT**, and its field paths are merged into the response
  `redactions` list alongside any policy-driven redactions.
- The DLP classification is fed into the policy engine's `EvaluationInput` so
  conditions like `data.classification == "restricted"` work even when the
  caller didn't pass one.

The runtime response now carries `risk_score`, `risk_severity`, and
`data_classification`. Non-`ALLOW` decisions record the classification and the
detector list into the audit event.

## Endpoints

```
POST /v1/runtime/evaluate                 # risk_score is now the real 7-factor score

POST /v1/risk/score                        # full factor breakdown (PRD §14 posture)

POST /v1/data-security/scan                # ad-hoc scan of text / a payload
GET  /v1/data-security/detectors           # detector list + default action table
GET/POST        /v1/data-security/classifications
GET/POST/PATCH/DELETE  /v1/data-security/policies
```

## Deferred

Real behavioral baselines (Step 8), health-data and source-code detectors,
customer-tunable factor weights, redaction actually applied to the outgoing
payload by the SDK (Step 5).
