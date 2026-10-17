# WP-2

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

Bare `flush()` drains every open window whose start is at or before the watermark, then calls `tick(watermark)`. `flush(now)` still closes only windows whose end is at or before `now`. A backward step inside the open window is accepted. `reorderMs` only extends tolerance before that window. After a drain, an event in the closed window is `LATE_EVENT`. `went-silent` stays on `tick()`.

## Tests added

`event-time.test.js` covers the drain, `flush(now)`, late events after a drain, in-window reorder, and the 2 s and 10 s skew cases. `went-silent.test.js` covers an unplugged camera, `forget()`, and a restart ticked at the watermark.

## Fast check

```
✔ retries, then sends the HMAC header (0.917167ms)
✔ throws after the last failed attempt (0.295875ms)
ℹ tests 101
ℹ suites 0
ℹ pass 101
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 72443.960583
```

## Thresholds

| Item                    | Before                                                            | After                                  |
| ----------------------- | ----------------------------------------------------------------- | -------------------------------------- |
| bare `flush()`          | `Date.now()`, then the watermark, and the open window stayed open | drains windows whose start ≤ watermark |
| in-window backward step | `CLOCK_JUMP` when `reorderMs` is 0                                | accepted                               |
| `reorderMs`             | not an option                                                     | 0                                      |
| `went-silent`           | next event                                                        | `tick()`                               |
