# Likelihood-ratio versus additive scoring

Measured on this machine. The likelihood-ratio option stays off by default.

| corpus            | result                                                                 |
| ----------------- | ---------------------------------------------------------------------- |
| synthetic fixture | not scored here; the option is off and the anomaly stream is unchanged |
| IoT-23            | needs dataset run by a person                                          |

The seed table is `packages/core/src/data/lr.json`. `eval/fit-lr.mjs` writes `eval/results/lr-proposal.json` and does not edit the seed.
