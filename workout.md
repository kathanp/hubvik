# hubvik workout — how to measure what fails

This playbook matches what the project already defines: **feedback**, **shadow mode**, and **pilots** (see [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md) and the shadow / C10 rules in [`docs/SPEC.md`](docs/SPEC.md)). Product boundary context: [`docs/features.md`](docs/features.md).

You don’t learn failures by guessing inside the npm package. You get them from **labeled live use** — and hubvik already has hooks for that. Core stays **offline** (no secret phone-home).

---

## 1. You measure first (before random users)

- Run public captures you control: IoT-23 / CICIoT via `eval/` (you already have some numbers; FP gate still fails).
- Run a **30-day pilot** on one home + one building (that’s an open gate in the spec). You own the gateways; you see which detectors fire on real quiet traffic.

---

## 2. Design partners / early npm users (voluntary)

Ask integrators to:

1. Run with normal `anomaly` listeners (and optionally `shadow: true`).
2. When an operator says “noise” or “real,” call the built-in API:

```js
engine.feedback(anomalyId, 'fp'); // or 'tp', 'benign-true', 'unknown'
```

3. Periodically send you **aggregated** exports (not raw PCAP unless they agree):
   - `engine.exportLabels()` — JSONL of verdicts
   - `engine.stats().precision` — per-detector FP rates; warns `NOISY_DETECTOR` when `fpRate > 0.5` and `n >= 10`
   - counts: detector id → how often it fired / was marked FP

That’s how you learn **which** detectors fail in the wild without turning npm into spyware.

### Pilot checklist (copy for partners)

- [ ] Engine running on a real gateway feed (conntrack / dnsmasq / Zeek / Suricata as available)
- [ ] `tiers` set to match what you actually send
- [ ] Optional: `shadow: true` (or a list of shadow ids) if collecting shadow evidence
- [ ] Operator labels alerts weekly with `feedback(..., 'tp' | 'fp' | ...)`
- [ ] After 7–30 days: send `exportLabels()` + note of `stats().precision` / noisy ids
- [ ] No raw PCAP unless both sides agree in writing

---

## 3. What “failed” means in practice

| Signal                                            | Meaning                            |
| ------------------------------------------------- | ---------------------------------- |
| High `fp` labels on one id                        | Too noisy → tighten or keep shadow |
| Almost never fires on known attacks in eval/pilot | Blind → improve that one detector  |
| Shadow fires a lot, live stays quiet              | Candidate to study before promote  |

---

## 4. What not to do

- Don’t auto-upload user traffic from the package (against offline design + trust).
- Don’t wait for “all npm users” — start with **1–2 pilots** who agree to label for 30 days.
- Don’t promote a shadow detector to live without evidence (shadow rule in the spec).
- Don’t invent detection rates; only publish numbers produced by scripts / agreed pilot exports in this repo.

---

## Bottom line

Failed measures come from **pilots + `feedback()` labels + eval**, not from the library magically knowing. Recruit a few gateway developers, give them a short “label FP/TP weekly, send `exportLabels`” playbook, and fix the noisiest ids first.

---

## Future path — can we make money? (B2B)

Yes — **B2B around an npm detector is possible**, but the money is rarely “people pay to `npm install`.” Apache-2.0 core stays free to embed; you charge for **trust, ops, and product** around it.

### Realistic money path (gateway / hub vendors)

**1. Now → credibility (little or no revenue)**  
Ship clear scope (detector only), docs, adapters. Close measurement: eval + 1–2 paid or free **design-partner pilots**. Without FP/pilot evidence, enterprise buyers won’t pay.

**2. Design partners (first dollars)**  
Gateway / OpenWrt / BMS vendors embed hubvik. You charge for:

- integration help (adapters, tiers, SIEM export)
- private Slack / office hours
- pilot success criteria (FP/device-day, which ids to enable)

**3. License + support (core B2B)**  
Keep npm core open (or “open core”). Sell:

- **annual support** (SLA, security response, upgrade guidance)
- **commercial license add-on** only if you add _separate_ proprietary bits (hosted console, certified builds, indemnity) — don’t try to re-license pure Apache code as “pay to use”
- optional **indemnity / vendor questionnaire pack** (buyers pay for paperwork)

**4. Hosted product (higher margin)**  
Vendor (or you) runs:

- optional cloud: ingest `exportLabels` / anomaly summaries (opt-in only)
- dashboard, fleet compare, policy packs, detector tuning
- “managed detection” for their customers

hubvik core stays report-only on the gateway; **your SaaS** is where subscription ARR lives.

**5. Marketplace / OEM**  
White-label: “Powered by hubvik” inside their hub app. Per-device or per-gateway SKU they resell; you take OEM fee.

### What usually does _not_ print money

- Expecting random npm downloads to convert
- Selling “blocks cyber attacks” (you don’t)
- Bundling auto-block / MITM (breaks your design and trust)

### Simple future path (one line)

**Open detector library → paid pilots/support with gateway OEMs → optional hosted console + OEM SKUs → enterprise support/indemnity.**
