# Likelihood-ratio versus additive scoring

Measured on the synthetic fixture. The likelihood-ratio option stays off by default.

Dataset: synthetic. Attack instances: 25. Benign device-days: 3.

| scoring  | annotations | anomaly false positives | anomaly FP/device-day                                        | alert false positives | alert FP/device-day                                          | detection                              |
| -------- | ----------- | ----------------------- | ------------------------------------------------------------ | --------------------- | ------------------------------------------------------------ | -------------------------------------- |
| additive | off         | 0                       | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 0                     | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) |
| lr       | off         | 0                       | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 0                     | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) |
| additive | on          | 0                       | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 0                     | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) |
| lr       | on          | 0                       | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 0                     | 0 per benign device-day (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) |

IoT-23: needs dataset run by a person.

The seed table is `packages/core/src/data/lr.json`. `eval/fit-lr.mjs` writes `eval/results/lr-proposal.json` and does not edit the seed.
