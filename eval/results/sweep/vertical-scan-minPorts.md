# Sweep vertical-scan.minPorts

Dataset: synthetic. 6 points. The default was not changed.

| value | detection                              | FP/device-day                          | precision | recall |
| ----- | -------------------------------------- | -------------------------------------- | --------- | ------ |
| 5     | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) | 0 (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 1         | 0.8000 |
| 10    | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) | 0 (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 1         | 0.8000 |
| 15    | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) | 0 (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 1         | 0.8000 |
| 20    | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) | 0 (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 1         | 0.8000 |
| 25    | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) | 0 (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 1         | 0.8000 |
| 30    | 20/25 = 80.0% (95% Wilson 60.9%–91.1%) | 0 (0/5 = 0.0% (95% Wilson 0.0%–43.4%)) | 1         | 0.8000 |

Monotonicity: false positives do not rise as the threshold rises.

## Proposal

Proposal: vertical-scan.minPorts = 15. Expected cost 4 with fp=1, miss=20. The default is unchanged. Cost weights are the operator's choice.
