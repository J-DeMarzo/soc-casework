# CASE-YYYY-NNN: <short title>

| | |
|---|---|
| **Date** | YYYY-MM-DD |
| **Analyst** | demarzo |
| **Severity** | Low / Medium / High / Critical |
| **Verdict** | True positive / Benign true positive / False positive |
| **ATT&CK** | Txxxx.xxx: Technique name |
| **Detection** | [`<file>.spl`](https://github.com/J-DeMarzo/enterprise-homelab/blob/<commit>/detections/<file>.spl) (link the commit that fired) |

## 1. Alert
What fired, when, and on which host or user. Include the alert-queue entry: a screenshot in `evidence/` or the SPL output.

## 2. Triage
First five minutes: is it real? Which data confirms or rules it out? What's the likely impact?

## 3. Investigation
The questions asked and the SPL that answered them. Link each answer to its evidence file.

```spl
index=... sourcetype=...
| ...
```

## 4. Timeline
| Time (UTC) | Host | Event | Source |
|---|---|---|---|
| | | | |

## 5. Indicators
| Type | Value | Context |
|---|---|---|
| IP / hash / user / process | | |

## 6. Conclusion
What happened, how far it got, and whether it was contained.

## 7. Response and recommendations
What an analyst would do in production: containment, eradication, escalation.

## 8. Detection improvements
What was tuned or added as a result, with links to the commits in enterprise-homelab.

## Evidence
| File | What it shows |
|---|---|
| [`evidence/`](evidence/) | |

## Appendix: emulation details
How the activity was generated (tool, command, Atomic test ID). This is kept separate so the investigation above reads as if it were blind.
