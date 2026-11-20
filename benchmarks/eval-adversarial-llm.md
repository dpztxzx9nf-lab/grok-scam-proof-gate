# Eval report: adversarial-llm

Offline run. No live Grok API call was made. Do not describe these numbers as live Grok scores.

| Metric | Result |
| --- | --- |
| Cases | 101 |
| Exact accuracy | 100.0% (101/101) |
| Policy accuracy | 100.0% (101/101) |
| Scam recall | 100.0% (76/76) |
| Precision (likely_scam) | 100.0% (76/76) |
| False-safe rate | 0.0% (0/76) |
| False-alarm rate | 0.0% (0/19) |
| Mean latency | 0.37 ms |
| Model downgrades blocked | 82 |

False-safe rate is `likely_scam` cases whose final verdict was `safe`.
False-alarm rate is benign (`safe`) cases whose final verdict was `likely_scam`.
Scam recall counts a `likely_scam` case as caught when the final verdict is `likely_scam` or `caution`.

## Categories

| Category | Cases | Exact | Recall | False-safe | False alarms |
| --- | ---: | ---: | ---: | ---: | ---: |
| ambiguous_caution | 6 | 6/6 | n/a | 0 | 0 |
| bank_fraud_impersonation | 4 | 4/4 | 4/4 | 0 | 0 |
| benign_appointment | 4 | 4/4 | n/a | 0 | 0 |
| benign_family | 4 | 4/4 | n/a | 0 | 0 |
| benign_local_tech | 3 | 3/3 | n/a | 0 | 0 |
| benign_official | 8 | 8/8 | n/a | 0 | 0 |
| check_overpayment | 3 | 3/3 | 3/3 | 0 | 0 |
| crypto_atm | 3 | 3/3 | 3/3 | 0 | 0 |
| fake_virus_tech_support | 8 | 8/8 | 8/8 | 0 | 0 |
| gift_card | 4 | 4/4 | 4/4 | 0 | 0 |
| government_impersonation | 4 | 4/4 | 4/4 | 0 | 0 |
| grandparent_emergency | 3 | 3/3 | 3/3 | 0 | 0 |
| isolation_secrecy | 3 | 3/3 | 3/3 | 0 | 0 |
| lookalike_phishing | 9 | 9/9 | 9/9 | 0 | 0 |
| prompt_injection | 8 | 8/8 | 8/8 | 0 | 0 |
| remote_access | 4 | 4/4 | 4/4 | 0 | 0 |
| sms_lure | 10 | 10/10 | 10/10 | 0 | 0 |
| spoofed_email | 9 | 9/9 | 9/9 | 0 | 0 |
| wire_zelle | 4 | 4/4 | 4/4 | 0 | 0 |
