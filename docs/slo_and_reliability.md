# Service Level Objectives (SLOs), Error Budgets & Reliability

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  
Document: **SLO & Reliability Engineering Guide**  

---

## 1. Overview & Framework

PRIVGUARD AI establishes formal Service Level Objectives (SLOs) and Service Level Indicators (SLIs) using Google SRE reliability principles. These SLOs govern operational availability, latency tolerances, and non-negotiable security guarantees.

---

## 2. Defined Service Level Objectives

| SLO Name | Target | Measurement Window | Error Budget | Indicator (SLI) |
| :--- | :--- | :--- | :--- | :--- |
| **API Availability** | **99.9%** | 30 Days (Rolling) | 0.1% (~43.2 min) | Ratio of non-5xx responses over total HTTP requests. |
| **Gateway Latency** | **95.0%** | 30 Days (Rolling) | 5.0% requests | Requests completing in $< 500\text{ ms}$. |
| **Security Canary Pass** | **100.0%** | 24 Hours (Rolling) | 0.0% (Zero tolerance) | Ratio of passing canaries over total executed. |
| **Memory KMS Availability** | **99.95%** | 30 Days (Rolling) | 0.05% (~21.6 min) | Successful DEK wrap/unwrap operations. |

---

## 3. Multi-Window Multi-Burn-Rate Alerting

Rather than alerting on transient latency spikes or raw error counts, PRIVGUARD alerts on **Error Budget Burn Rates**. A burn rate of 1.0 means the service will consume exactly 100% of its error budget over the 30-day window. Higher burn rates indicate catastrophic degradation requiring immediate intervention.

```
Burn Rate = (Observed Error Ratio) / (Allowed Error Ratio)
```

### Alert Thresholds
| Burn Rate | Time to Exhaust Budget | Monitoring Window | Severity | Action |
| :--- | :--- | :--- | :--- | :--- |
| **14.4x** | 2 Days (2% in 1 hr) | 1 Hour | `CRITICAL` | Immediate PagerDuty page to primary on-call. |
| **6.0x** | 5 Days (5% in 6 hr) | 6 Hours | `HIGH` | Alert dispatched to `#secops-alerts` Slack channel. |
| **1.0x** | 30 Days (10% in 3 days) | 3 Days | `MEDIUM` | Jira ticket created for next engineering sprint. |

---

## 4. Implementation in Python (`app/observability/slo.py`)

The burn rate calculator ensures standards-compliant, finite float representations (preventing `float("inf")` serialization crashes in JSON APIs):

```python
def calculate_burn_rate(target: float, current_rate: float) -> float:
    allowed_error_ratio = 1.0 - (target / 100.0)
    if allowed_error_ratio <= 0.0:
        # Zero tolerance SLO (100% target): Any failure burns the budget
        return 100.0 if current_rate < target else 0.0
    
    actual_error_ratio = max(0.0, 1.0 - (current_rate / 100.0))
    raw_burn = actual_error_ratio / allowed_error_ratio
    return float(min(100.0, round(raw_burn, 2)))
```

---

## 5. Next.js SLO Scorecard Visualizer

The Next.js Control Center exposes the live SLO health card at `/monitoring`:
- **Current Performance**: Real-time calculated SLI percentage.
- **Budget Remaining**: Percentage and time remaining until budget depletion.
- **Status Indicator**: `NOMINAL` (Burn rate $< 1.0$), `DEGRADED` ($1.0 \le \text{Burn} \le 6.0$), `BURNING` ($\text{Burn} > 6.0$).
