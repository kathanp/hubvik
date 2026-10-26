# Changelog

## 0.1.1

Flow events include `bytesIn`, `pktsIn`, and `durationMs`, so the engine accepts them. ICMP, GRE, and ESP keep their names. Any other protocol stays a number. A field shorter than its width is skipped instead of throwing.

## 0.1.0

UNVERIFIED IPFIX and NetFlow v9 parser.
