# @hubvik/adapter-unbound

UNVERIFIED. Written from Unbound's documented `log-queries` / `log-replies` text, not from a capture.

Accepts lines containing `query:` or `reply:`:

```
info: 10.0.0.2 www.example.com. A IN query
info: 10.0.0.2 www.example.com. A IN NOERROR reply 1.2.3.4
```

`createParser({ device, now }).write(line)` returns dns events and never calls `feed`.
