# @hubvik/indicators-file

`parseIndicators(text)` and `loadIndicatorFile(file)` turn a file the host already downloaded into the array `engine.loadIndicators()` accepts.

Accepted text: a JSON array of indicator objects, JSON lines, or `type value [source]` lines. `#` comments are skipped. There is no bundled feed and no network call. A file over 100,000 rows is rejected. Pass `max` to use a smaller cap.
