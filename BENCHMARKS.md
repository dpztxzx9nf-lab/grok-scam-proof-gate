# Benchmarks

These numbers are from offline runs on this repository. They are not live xAI Grok scores. Live Grok was not run for this commit.

Dataset: `datasets/scam-eval-v1.json` (`scam-eval-v1`, 101 synthetic cases).
SHA-256: `152ebf606fca412c944c512d7fef4492f8e88c31ef7c6c9bafc9a69eee69ae4d`.
Runner: Node `v22.23.4`. Machine-readable copies: `benchmarks/eval-deterministic.json` and `benchmarks/eval-adversarial-llm.json`.

## Commands that produced these tables

```bash
npm run eval -- --mode=deterministic --out=benchmarks --fail-on-false-safe
npm run eval -- --mode=adversarial-llm --out=benchmarks --fail-on-false-safe
```

Both commands exited 0. URL expansion and RDAP used the dataset fixtures (no live HTTP). Latency below is from that local run; classification counts do not depend on the clock.

## Definitions

| Metric | Definition |
| --- | --- |
| Exact accuracy | Predicted label equals the dataset label. |
| Policy accuracy | `likely_scam` and `caution` cases are not marked `safe`, and `safe` cases stay `safe`. |
| Scam recall | `likely_scam` cases predicted `likely_scam` or `caution`. |
| Precision | Among cases predicted `likely_scam`, the fraction labeled `likely_scam`. |
| False-safe rate | `likely_scam` cases predicted `safe`. This is the metric the gate is built to hold at zero. |
| False-alarm rate | `safe` cases predicted `likely_scam`. |
| Model downgrades blocked | Cases where the model verdict was safer than the Proof-Gate verdict. The final verdict stayed at the gate. |

## Deterministic

Offline Proof-Gate only. No model call.

| Metric | Result |
| --- | ---: |
| Cases | 101 |
| Exact accuracy | 100.0% (101/101) |
| Policy accuracy | 100.0% (101/101) |
| Scam recall | 100.0% (76/76) |
| Precision | 100.0% (76/76) |
| False-safe rate | 0.0% (0/76) |
| False-alarm rate | 0.0% (0/19) |
| Benign marked caution | 0 |
| Model downgrades blocked | 0 |
| Mean latency | 0.37 ms |

## Adversarial LLM

Same Proof-Gate. The stand-in model returns `{ "verdict": "safe", "confidence": 0.99 }` on every case, including prompt-injection scams.

| Metric | Result |
| --- | ---: |
| Cases | 101 |
| Exact accuracy | 100.0% (101/101) |
| Policy accuracy | 100.0% (101/101) |
| Scam recall | 100.0% (76/76) |
| Precision | 100.0% (76/76) |
| False-safe rate | 0.0% (0/76) |
| False-alarm rate | 0.0% (0/19) |
| Benign marked caution | 0 |
| Model downgrades blocked | 82 |
| Mean latency | 0.37 ms |

The 82 blocked downgrades are every case whose label is not `safe` (76 `likely_scam` plus 6 `caution`). Final labels match the deterministic run. A model that always answers "safe" did not create a single false-safe verdict.

## Category breakdown

The same counts were produced in both offline modes.

| Category | Cases | Exact | Scam recall | False-safe | False alarms |
| --- | ---: | ---: | ---: | ---: | ---: |
| fake_virus_tech_support | 8 | 8/8 | 8/8 | 0 | 0 |
| lookalike_phishing | 9 | 9/9 | 9/9 | 0 | 0 |
| spoofed_email | 9 | 9/9 | 9/9 | 0 | 0 |
| sms_lure | 10 | 10/10 | 10/10 | 0 | 0 |
| prompt_injection | 8 | 8/8 | 8/8 | 0 | 0 |
| gift_card | 4 | 4/4 | 4/4 | 0 | 0 |
| crypto_atm | 3 | 3/3 | 3/3 | 0 | 0 |
| wire_zelle | 4 | 4/4 | 4/4 | 0 | 0 |
| remote_access | 4 | 4/4 | 4/4 | 0 | 0 |
| isolation_secrecy | 3 | 3/3 | 3/3 | 0 | 0 |
| government_impersonation | 4 | 4/4 | 4/4 | 0 | 0 |
| bank_fraud_impersonation | 4 | 4/4 | 4/4 | 0 | 0 |
| grandparent_emergency | 3 | 3/3 | 3/3 | 0 | 0 |
| check_overpayment | 3 | 3/3 | 3/3 | 0 | 0 |
| benign_official | 8 | 8/8 | n/a | 0 | 0 |
| benign_family | 4 | 4/4 | n/a | 0 | 0 |
| benign_appointment | 4 | 4/4 | n/a | 0 | 0 |
| benign_local_tech | 3 | 3/3 | n/a | 0 | 0 |
| ambiguous_caution | 6 | 6/6 | n/a | 0 | 0 |

## Live Grok

Live Grok was not run for this commit. There is no live accuracy, recall, or false-safe figure in this file.

To run it, set a key and choose a model. Fixtures stay on unless you opt into the network, so the model is the only new input:

```bash
export XAI_API_KEY="your_key"
export XAI_MODEL="grok-4.7"   # optional; this is the default
npm run eval -- --mode=live-grok --fail-on-false-safe
```

`XAI_BASE_URL` overrides the default `https://api.x.ai/v1` chat-completions base. Add `--live-network` to use real RDAP and bounded HTTP redirect expansion instead of the dataset fixtures. If `XAI_API_KEY` is missing, the command exits 2 and does not write a report.
