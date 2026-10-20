# Contributing

## Before you change a detector

Read `docs/SPEC.md` for that row and `docs/RULES.md`. If the spec is ambiguous, add the question to `docs/QUESTIONS.md` and wait. Do not pick a threshold that the spec does not state.

## Checks

```
npm ci
npm run check
```

`npm run gate` is the release check: tests, coverage, pack size, spec coverage, fuzz, and the bench budgets. It is slow. Run it before a release commit.

## Commits

Small commits. Conventional messages, for example `feat(detector): horizontal-scan` or `fix(engine): flush closes only ended windows`.

## Packages

A new adapter or exporter is its own package under `packages/`, version `0.1.0`, `dependencies: {}`, Apache-2.0. It returns data. It does not call `feed`, open a socket, or spawn a process.

Parsers written from documentation and not run on a real log say `UNVERIFIED` in the README and the source header.

## What not to send

No secrets, no `.npmrc` auth lines, and no dataset files that the repo does not already vendor. Detection-rate claims belong in `eval/results/` only after `eval/` produced them.
