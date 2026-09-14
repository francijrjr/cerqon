# CERQON

> **Security & Control for Autonomous AI**  
> *Know what your AI agents can access before they act.*

---

CERQON is an open-source security scanner for AI agents and MCP configurations. A security control plane for autonomous AI is the long-term vision.

As organizations deploy AI agents with autonomous tooling (Model Context Protocol / MCP, shell execution, database connectors, and filesystem access), security boundaries become blurred. 

**The core question CERQON answers:**
> **“What can this AI agent access, modify, or execute if compromised?”**

CERQON provides static analysis, risk scoring, credential masking, and governance for AI agent configurations, preventing excessive blast radiuses and dangerous capability chains before agents execute actions.

---

## Key Features

- 🔍 **Discovery & Static Analysis**: Automatically discovers MCP servers, agent manifests, and tool configurations across Claude Desktop, Cursor, VS Code (Roo/Cline), and generic environments.
- 🛡️ **CERQON Rules Engine**: Analyzes configurations against a structured catalog of agent security vulnerabilities (`CQ-001` through `CQ-012`).
- 📁 **Filesystem Blast Radius**: Identifies unconstrained filesystem mounts (`/`, `C:\`, home directories) that expose host operating system files.
- 🔑 **Secret Detection & Redaction**: Detects hardcoded API keys, private keys, and tokens in agent configurations with masking (`sk-****...****`).
- ⚡ **Shell Capability Detection**: Flags unrestricted execution capabilities (`bash`, `powershell`, `cmd`, `exec`) lacking explicit confirmation guardrails.
- 📊 **Security Score (0 - 100)**: Quantitative posture score with transparent deductions based on severity.
- 🔒 **Local-First & Defensive**: Designed to operate locally with no telemetry required.

---

## Quick Start

### Installation

```bash
# Global install (npm or pnpm)
npm install -g @cerqon/cli

# Or run directly via npx
npx @cerqon/cli scan
```

### Usage

```bash
# Scan current workspace
cerqon scan .

# Verbose output
cerqon scan . --verbose

# JSON report (for CI/CD pipelines)
cerqon scan . --json

# Export report to file
cerqon scan . --output cerqon-report.json

# Inspect available security rules
cerqon rules

# Verify environment & dependencies
cerqon doctor

# Check version
cerqon version
```

---

## Architecture

CERQON uses a modular monorepo architecture:

```
cerqon/
├── apps/
│   └── cli/             # CLI presentation layer (Commander.js, Chalk, Ora)
├── packages/
│   ├── types/           # Core domain contracts, Finding, MCPServer, ScanResult
│   ├── core/            # Safe masking, file helpers, pattern matching
│   ├── adapters/        # Agent config parsers (Claude, Cursor, VSCode, Generic)
│   ├── risk-engine/     # CERQON rule definitions and 0-100 scoring engine
│   ├── reporters/       # Terminal card formatter and JSON reporter
│   ├── policy-engine/   # Policy enforcement interfaces
│   └── scanner/         # Scan orchestration pipeline
├── rules/               # Canonical rule taxonomy & documentation
└── examples/            # Reference configurations (insecure vs. secure)
```

### Scan Flow

```
Discovery
   ↓
Configuration Parsing
   ↓
Agent & MCP Identification
   ↓
Tool & Capability Extraction
   ↓
Permission & Path Analysis
   ↓
Secret Detection (Masked)
   ↓
Risk Correlation & Scoring
   ↓
Security Report
```

---

## CERQON Rules Catalog

| Rule ID | Title | Severity | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| `CQ-001` | **Excessive Tool Permission** | `HIGH` | Architecture | Tools granted wildcard or broad action permissions |
| `CQ-002` | **Unrestricted Filesystem Access** | `CRITICAL` | **Active** | Root (`/`, `C:\`) or unrestricted filesystem mount exposed to agent |
| `CQ-003` | **Exposed Agent Secret** | `CRITICAL` | **Active** | Hardcoded API keys, tokens, or credentials in configuration |
| `CQ-004` | **Excessive OAuth Scope** | `MEDIUM` | Architecture | Overly broad OAuth scopes granted to agent integrations |
| `CQ-005` | **Unsafe Shell Capability** | `HIGH` | **Active** | Unrestricted terminal/shell execution capability (`bash`, `powershell`, `exec`) |
| `CQ-006` | **Untrusted MCP Server** | `HIGH` | **Active** | Server connecting to unverified remote endpoints or unpinned commands |
| `CQ-007` | **Missing Human Approval** | `MEDIUM` | Architecture | Mutating actions permitted without human-in-the-loop validation |
| `CQ-008` | **Agent Network Exposure** | `HIGH` | Architecture | Agent exposed to unauthenticated inbound network access |
| `CQ-009` | **Tool Definition Drift** | `LOW` | Architecture | Local tool definition deviates from approved registry hash |
| `CQ-010` | **Missing Audit Trail** | `LOW` | Architecture | Agent execution logging or session audit disabled |
| `CQ-011` | **Cross-Agent Data Exposure** | `HIGH` | Architecture | Shared memory or filesystem context between untrusted agents |
| `CQ-012` | **Dangerous Capability Chain** | `CRITICAL` | Architecture | Toxic combinations (e.g. Filesystem Read + Secret Access + Shell Outbound) |

---

## Roadmap

- [x] **0.1 - Core Foundation & CLI**
  - Modular monorepo with `@cerqon/*` packages
  - MCP configuration parsers (Claude Desktop, Cursor, VS Code, Generic)
  - Implemented rules: `CQ-002`, `CQ-003`, `CQ-005`, `CQ-006`
  - Dynamic 0-100 Security Score
  - Terminal card reporter and JSON output
- [ ] **0.2 - Governance & CI**
  - SARIF standard output format
  - Expanded agent adapters (LangChain, AutoGen, CrewAI manifests)
  - GitHub Action (`cerqon-action@v1`) with fail-on thresholds
- [ ] **0.3 - Capability Graph**
  - Dependency & permission graphing (Agent → Tool → Capability → Resource)
  - Automated toxic capability chain correlation (`CQ-012`)
- [ ] **0.4 - Policy Engine**
  - Custom policy-as-code definitions (`cerqon.policy.yaml`)
- [ ] **1.0 - CERQON Runtime & Gateway**
  - Real-time MCP proxy gateway with dynamic request inspection and authorization

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
