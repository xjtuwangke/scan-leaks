# scan-leaks repository conventions

## Scope

This is an independent secret-leak scanner repository and does not depend on
the parent `ai-hub` repository.

## Build & Run

- Install dependencies: `npm install`
- Build: `npm run build`
- Run: `npm run scan -- --help`

## Code style
- Keep `summary`/`json`/`sarif` output compatibility with parameters and formats.
- Prefer scan detection logic changes under `src/secret-scan/*`.
- Preserve readable errors for plugin loading and rule parsing failures.
