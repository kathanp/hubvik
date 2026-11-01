<!-- docs/QUESTIONS.md -->

# Questions

## Resolved

1. **Q-1. When a WP-1 threshold moves, which version bumps?** Resolved 2026-10-17. Keep core at 0.4.0 until the end of WP-8, then bump to 0.5.0 once. A moved threshold does not bump the version by itself.

2. **Q-2. Is `minLearnWindows: 500` right for every device?** Resolved 2026-10-17. The default stays 0. Per-class values are not added in this run. 500 suits devices with a steady heartbeat; leave at 0 for devices that can be idle for days, such as printers.

3. **Q-3. When does `reorderMs` default change from 0 to 5000?** Resolved 2026-10-17. It stays 0 through all of 0.5. Examples that merge adapters set 5000.

4. **Q-4. What severity is `proxy-sdk-traffic` on a `smart-tv`?** Resolved 2026-10-17. Medium on `smart-tv` and `tv-box`, high otherwise. `lan-via-proxy` still escalates.

5. **Q-5. `smart-tv` upload cap and browser JA4.** Resolved 2026-10-17. The upload cap stays 50000000. `browser-mimic` will read `allowsBrowserJa4` from the class file in WP-6. That flag is true for `tv-box`, `nas`, `hub`, and `smart-tv`.

6. **Q-6. What does `flush()` with no argument close?** Resolved 2026-10-17. It is an end-of-input drain. It closes every open window whose start is ≤ the watermark, including the window that contains the watermark, then calls `tick(watermark)`. `flush(now)` closes only windows whose end is ≤ `now`.

7. **Q-7. Does `reorderMs: 0` reject a backward step inside the current window?** Resolved 2026-10-17. No. A backward step inside the current open window is always accepted. `reorderMs` only extends tolerance before that window.

8. **Q-8. May the idle-window acceptance test stop reading `state.samples`?** Resolved 2026-10-18. Yes. The assertion checks the behavior: the same scenario stays quiet at 2,100,000 bytes, fires at 5,000,000, and the detector's learned count includes the idle windows. Nothing else in that test file changes. This is for WP-11.

9. **Q-9. Do shadow anomalies reach exporters when a host subscribes to `anomaly` only?** Resolved 2026-10-18. No. They reach exporters only when the host subscribes to `shadow-anomaly`.

10. **Q-10. When do sharded workers ship?** Resolved 2026-10-18. Sharding is built in inline mode only until a Raspberry Pi 4 bench exists.

11. **Q-11. Is a text-only nftables renderer acceptable?** Resolved 2026-10-18. Response hints are text only and default off.

12. **Q-12. Does `matter-new-controller` stay in 0.8?** Resolved 2026-10-18. Yes. It stays at 0.8 in shadow mode.

13. **Q-13. Which text governs WP-10.1?** Resolved 2026-10-18. The newer prompt wins. `docs/SPEC.md` was updated to match it. Rel 0.8, `enabled: false` until WP-12, then `mode: 'shadow'`.

14. **Q-15. GitHub owner.** Resolved 2026-10-20. The personal account `kathanp/hubvik`. ADR 0001 already used `github.com/kathanp` for the name check, and `github.com/hubvik` is taken. No organization name was given.

15. **Q-16. IoT-23 `Background` and `No Label`.** Resolved 2026-10-20. Excluded from the detection count and from benign device-days, and counted on their own line when any such events are present. This is the spec default. The published IoT-23 rate was not re-run, so it stays the number in `eval/results/iot23-malware/iot23.md`.

16. **Q-17. Ratio-ring headroom.** Not open. The 2026-10-20 clean-clone re-gate left 32.58 KB (defaults) and 28.89 KB (`shadow: true`).

17. **Q-18. Shadow median as a gate.** Resolved 2026-10-20. Yes, after two consecutive gate runs are under 10 µs. The runs are 7.92 µs (`2f75270`) and 7.58 µs (`ac4d8d3`). The line is not in `bench/run.js` until a person approves it (D-44).

18. **Q-19. First publish dist-tag.** Resolved 2026-10-20. `next`, until 1.0. The README status line stays the prototype line. Nothing is published.

19. **D-44 collision.** Resolved 2026-10-21. D-44 stays the shadow-median gate. The 0.5 µs CPU cap is D-85. No existing decision was renumbered.

20. **Q-20. Which level do the C6.3 gates use once `alerts: true` exists?** Resolved 2026-10-21. Spec default: the anomaly level until the 30-day pilot. Alert-level numbers are published next to them.

21. **Q-21. What does `scoring: 'lr'` use before fitted values exist?** Resolved 2026-10-21. Spec default: the D-48 seed table. The option stays off by default.

22. **Q-22. Must `annotate()` take an HMAC key?** Resolved 2026-10-21. Spec default: no key. The never-affected list, the caps, `ANNOTATION_ABUSE`, and the G9 audit log carry the risk.

23. **Q-24. When do the B22 rows ship?** Resolved 2026-10-21. Spec default: Rel 1.1, shadow only, and only after C10 row 0.6 is ticked.

24. **Q-25. May the G2 digest hold a second non-critical alert until the day closes?** Resolved 2026-10-21. Spec default: yes. Critical and hard-rule alerts are never folded, and the digest still arrives the same day.

## Open

1. **Security contact.** `packages/core/SECURITY.md` points at GitHub private vulnerability reporting and does not list an email. What address should it use?

2. **Capped rings on `upload-ratio-shift` and `failed-connection-ratio`.** Those two keep capped rings because a 7-day learn exceeds the cap and streaming stats would change the golden. Revisit if memory headroom drops under 20 KB. The 2026-10-20 re-gate stayed above 20 KB, so Q-17 is not open.

3. **Q-14. Disclosure email for `SECURITY.md`?** Same as open question 1. Until an address is chosen, the release check leaves the missing email as a blocker.

4. **Q-23. Source and license of `src/data/words.json` for `dictionary-dga`.** Open. The detector file and `src/data/words.json` have been in the tree since 1.3.1. The 1.3.1 changelog says the list is 2,000 words of 3–5 letters from the public-domain system word list. A person still has to accept that source and license. The row stays shadow.

5. **Q-29. B24 starting values.** Open. Accept D-102 to D-106 for `dispersed-flood`, `txt-channel`, `inbound-lateral`, `short-lived-cert`, and `tls.cert.notBefore`? The rows are shadow only. The 0.6 gate stays open. This is the approval for the 1.6.0 detector docs.

6. **Q-30. B25 starting values.** Open. Accept D-107 to D-110 for `h2-fanout`, `onion-name`, `proxy-fanin`, and `scatter-udp`? The rows are shadow only. The 0.6 gate stays open. This is the approval for the 2.0.1 detector docs.

7. **Q-31. `egress-flood` outbound-only and learned updates at capacity.** Open. Spec says flood to an external destination; sibling flood rows require `direction: 'out'`. Requiring `out`, and updating an existing learned destination when the map is full, both move `test/diff/golden.json` baselines. Spec forbids editing that golden without a person decision. Approve the behavior and a golden refresh?

8. **Q-32. npm dist-tag.** D-41 says publish with tag `next` until 1.0. On 2026-10-31, `npm view hubvik dist-tags --json` returned `{ "latest": "3.2.0" }`. There is no `next` tag in that output. `npm view hubvik versions --json` lists 0.0.0-stage, 0.8.0, 1.0.0, 1.4.0, 1.5.0, 1.6.0, 2.0.1, 2.0.2, 2.0.3, 2.0.4, 2.1.0, 2.3.0, 3.0.1, 3.1.0, and 3.2.0. Options: move `latest` back and publish under `next`; keep `latest` and supersede D-41. Decision: person.

9. **Q-33. `words.json` shipped while Q-23 is open.** Q-23 asks for the source and license of `packages/core/src/data/words.json`. The 1.3.1 changelog says the file is 2,000 words of 3–5 letters from the public-domain system word list, and `dictionary-dga` is in that release. The file is still in the tree. Options: confirm a public-domain source and record it; or remove the file and disable `dictionary-dga` in a patch release. Decision: person.

10. **Q-34. Group C rows while C10 row 0.6 is open.** Rule 0.1, 0.8.1, and 0.9.1 say no group C detector row before C10 row 0.6. The tree has B22 rows from 1.0.0 (`dhcp-route-injection`, `wpad-hijack`, `ra-flood`, `karma-responder`, `cname-cloak`, `ja4-churn`, `lan-first-seen-domain`, `multivariate-outlier`, `sequence-surprise`, `flow-shape-change`, `dormant-reactivation`, `firmware-size-divergence`, `stun-turn-relay`, `port-knock`, `bacnet-bbmd-write`, `modbus-unit-sweep`, `mqtt-retained-command`, `rtsp-new-viewer`, `suppression-abuse`) and `dictionary-dga` from 1.3.1; B23 rows from 1.3.1 (`graph-contagion`, `doh-bypass`, `spectral-beacon`, `modbus-address-sweep`, `mqtt-will-takeover`); B24 rows from 1.6.0 (`dispersed-flood`, `txt-channel`, `inbound-lateral`, `short-lived-cert`); B25 rows from 2.0.1 (`h2-fanout`, `onion-name`, `proxy-fanin`, `scatter-udp`). They are shadow. C10 row 0.6 is still `[ ]`. Options: keep them shadow and amend the rule in a new spec section; or remove them. Decision: person.

11. **Q-35. Holdout after the bogon-destination severity change.** `eval/results/iot23-malware/iot23.md` still records `bogon-destination: 0 unique detections, 307 false positives, zero unique` and a proposal of 307 medium false positives over 72.7037175925926 benign device-days. `packages/core/CHANGELOG.md` for 2.1.0 says the severity is now info. The decision and the measurement use the same capture. Which IoT-23 captures become the holdout set, and does the 0.6 gate require a holdout number? Decision: person.

12. **Q-36. Published while the disclosure email is open.** Q-14 is open. `packages/core/SECURITY.md` has no disclosure email. The release check lists that missing email as a blocker. `hubvik` 3.2.0 is the npm `latest` tag. Options: confirm the email, or confirm GitHub private reporting alone is the policy. Decision: person.

13. **Q-37. Which bogon-destination false-positive count is current?** `eval/results/iot23-malware/iot23.md` counts 314 anomalies at medium or above and 4.31889881834587 per benign device-day, including 307 medium false positives for `bogon-destination`. `packages/core/CHANGELOG.md` 2.1.0 says that severity is info and the other medium false positives were unchanged. This run quotes the result file and does not pick the changelog. Which file should later docs cite, and does the result file need a new run before that citation changes? Decision: person.

14. **Q-38. `docs.versioned` is not in `.autopilot/protected.json`.** `docs/current/AUTOPILOT.md` shows a `docs.versioned` list of `README.md`, `docs/DEVELOPERS.md`, `docs/OPERATIONS.md`, and `docs/ARCHITECTURE.md`. The checked-in working copy of `.autopilot/protected.json` has `docs.mustMentionVersion` and no `docs.versioned` key. Options: add that key to `protected.json`, or drop the version-line rule from the playbook. Decision: person.

15. **Q-39. Approve the J3 core-profile membership rule?** SPEC section J3. [PROPOSED D-119]: the planned `core` profile is every hard rule (B10), every engine-integrity detector (B11), and every live detector whose tune suggestion is `keep`. If the tune scorecard has no `keep` row, the file is hard rules plus integrity only. The planning prompt numbered this Q-37. Q-37 is already the bogon-destination count question, so this is Q-39. Options: accept D-119, or pick a different membership rule before any profile code is written. Decision: person.

16. **Q-40. Approve the J6 family lists, and that families stay opt-in until a pilot shows fewer alerts with no lost incident?** SPEC section J6. [PROPOSED D-130] is the five lists in that section. The planning prompt numbered this Q-38. Q-38 is already the `docs.versioned` question, so this is Q-40. Options: accept those lists and keep `families` default `false` until a pilot shows fewer alerts and no replay loses its incident, or change the lists before the file is written. Decision: person.

17. **Q-41. Approve the J9 selftest scenario list and caps?** SPEC section J9. [PROPOSED D-136] is 16 scenarios. [PROPOSED D-137] is 10,000 events per scenario. [PROPOSED D-139] is reserved ids `__selftest-<n>` and documentation addresses `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`. The scenarios are horizontal scan, egress flood, DNS tunnel, new beacon, ARP gateway claim, OT dangerous op, and proxy backconnect. The planning prompt numbered this Q-39. That number is the core-profile question above, so this is Q-41. Options: accept that list and those caps, or change them before the file is written. Decision: person.

18. **Q-42. Approve the J10 readiness thresholds and the suggestLock rule?** SPEC section J10. [PROPOSED D-138]: `suggestLock` is true only when the score is at least 80, there is no open `SUSPICIOUS_LEARNING` reason, there is no hard-rule anomaly during learning, and the new-family rate in the last 48 h is at most 1 per day. Numeric weights that turn the existing inputs into the 0–100 score are not set in this plan. The planning prompt numbered this Q-40. That number is the family-list question above, so this is Q-42. Options: accept D-138 and set the weights in a later decision, or reject the thresholds before any readiness code is written. Decision: person.

19. **Q-43. Should 3.5.0 and 3.6.0 wait for the 30-day pilot result, or only for the earlier version's gate?** SPEC section 0.20. The plan says each later version requires the earlier version's gate. It does not decide whether 3.5.0 and 3.6.0 also wait for the pilot. The planning prompt numbered this Q-41. That number is the selftest question above, so this is Q-43. Options: wait for the 30-day pilot result, or start 3.5.0 once the 3.4.0 gate is met and 3.6.0 once the 3.5.0 gate is met. Decision: person.

## Resolved 2026-10-31

Appended. The open items above are unchanged.

20. **Q-32. npm dist-tag latest vs next.** Resolved 2026-10-31. Keep `latest`. D-41 is superseded (D-140). The README keeps the prototype line.

21. **Q-23 and Q-33. words.json shipped while its license is open.** Resolved 2026-10-31. Remove `words.json` and the `dictionary-dga` detector in 3.3.0 (D-141). Q-23 closes: removed, no source accepted.

22. **Q-14, open question 1, and Q-36. Security disclosure contact.** Resolved 2026-10-31. Contact is patelkathan244@gmail.com plus GitHub private vulnerability reporting. Acknowledge within 5 business days (D-142). That approves the response time in D-36. The address is the git user.email on this machine; the run prompt still said YOUR_SECURITY_EMAIL.

23. **Q-39. J3 core-profile membership rule.** Resolved 2026-10-31. D-119 is approved (D-143).

24. **Q-40. J6 family lists, opt-in until a pilot shows fewer alerts with no lost incident.** Resolved 2026-10-31. D-130 is approved (D-144). Families stay opt-in until that pilot.

25. **Q-41. J9 selftest scenarios and caps.** Resolved 2026-10-31. D-136, D-137, and D-139 are approved (D-145).

26. **Q-42. J10 readiness rule.** Resolved 2026-10-31. D-138 is approved as a rule (D-146). The numeric score weights stay open. J10 is 3.6.0.

27. **Q-43. Whether 3.5.0 and 3.6.0 wait for the pilot.** Resolved 2026-10-31. No. Each waits only for the previous version's gate (D-147). Families stay opt-in until the pilot.

28. **J4 pilot numbers and J7/J8 caps.** Resolved 2026-10-31. D-120 to D-129 and D-131 to D-135 are approved as starting values (D-148).

29. **J2 scorecard suggestion rule.** Resolved 2026-10-31. Approved as D-149. The gate is the detector's default severity C6.3 gate. No new rate was invented.

30. **Q-35. Holdout captures.** Resolved 2026-10-31. Every IoT-23 capture on disk other than iot23-malware is holdout (D-150). On this machine that is iot23-honeypot. Re-measure on holdout before the 0.6 gate.

31. **Q-38. docs.versioned is not in protected.json.** Resolved 2026-10-31. Add `docs.versioned` with README.md, docs/DEVELOPERS.md, docs/OPERATIONS.md, and docs/ARCHITECTURE.md (D-151). The open item above is unchanged. The directory `.autopilot/` stays gitignored, so a clone does not carry the file.
