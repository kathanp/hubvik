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

## Open

1. **Security contact.** `packages/core/SECURITY.md` points at GitHub private vulnerability reporting and does not list an email. What address should it use?

2. **Repository URLs.** `packages/core/package.json` has no `repository`, `bugs`, or `homepage`. Phase 0 does not create a remote. Add them when the GitHub repository exists.

3. **IoT-23 labels other than Benign and Malicious.** The joiner treats every `label` other than `benign` as an attack, including a future `Background` or empty detailed-label on a non-benign row. Should `Background` and `No Label` be benign instead?

4. **Capped rings on `upload-ratio-shift` and `failed-connection-ratio`.** Those two keep capped rings because a 7-day learn exceeds the cap and streaming stats would change the golden. Revisit if memory headroom drops under 20 KB.
