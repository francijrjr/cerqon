# Contributing to CERQON

Thank you for contributing to CERQON! We welcome community contributions to build the leading security control plane for autonomous AI.

## Monorepo Architecture

CERQON is organized as a pnpm monorepo:

- `apps/cli`: The Commander.js CLI application (`cerqon`).
- `packages/types`: Shared TypeScript interfaces and domain models.
- `packages/core`: Base utilities, path safety, and masking logic.
- `packages/adapters`: Agent and MCP configuration parsers.
- `packages/risk-engine`: CERQON rules repository and scoring logic.
- `packages/reporters`: Terminal and JSON output formatters.
- `packages/scanner`: Scan orchestrator coordinating discovery to reporting.
- `rules/`: Canonical rule definitions.

## Development Workflow

1. Install dependencies:
   ```bash
   pnpm install
   ```

2. Build all packages:
   ```bash
   pnpm run build
   ```

3. Run test suites:
   ```bash
   pnpm test
   ```

4. Run CLI locally:
   ```bash
   pnpm cerqon scan ./examples/insecure-agent
   ```

## Adding a New CERQON Rule

1. Check the rule taxonomy in `rules/`.
2. Implement the rule definition in `packages/risk-engine/src/rules/`.
3. Add corresponding unit tests in `packages/risk-engine/tests/` or `tests/`.
4. Ensure zero false positives on standard, secure agent configurations.
