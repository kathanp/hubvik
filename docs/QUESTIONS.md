# Questions

## Resolved

1. **Q-1. When a WP-1 threshold moves, which version bumps?** Resolved 2026-10-17. Keep core at 0.4.0 until WP-8, then bump to 0.5.0 once.

2. **Q-2. Is `minLearnWindows: 500` right for every device?** Resolved 2026-10-17. Not the single global recommendation. `minLearnWindows` is a per-class value in `src/data/classes/*.json`, overridable by the `createEngine` option. Recommended values: plug 500, camera 500, thermostat 300, hub 500, hvac-controller 500, tv-box 300, smart-tv 300, nas 300, printer 60. With no class, the engine default stays 0.

3. **Q-3. When does `reorderMs` default change from 0 to 5000?** Resolved 2026-10-17. It stays 0 until 0.6.

4. **Q-4. What severity is `proxy-sdk-traffic` on a `smart-tv`?** Resolved 2026-10-17. Medium on `smart-tv` and `tv-box`. `lan-via-proxy` still escalates.

## Open

1. **Security contact.** `packages/core/SECURITY.md` points at GitHub private vulnerability reporting and does not list an email. What address should it use?

2. **Repository URLs.** `packages/core/package.json` has no `repository`, `bugs`, or `homepage`. Phase 0 does not create a remote. Add them when the GitHub repository exists.
