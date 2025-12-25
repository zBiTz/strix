# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Strix is an open-source AI-powered security testing tool that uses autonomous agents to perform penetration testing. It runs target applications in Docker sandbox containers and uses LLMs to orchestrate security testing through a multi-agent architecture.

**Project Stats:**
- Version: 0.5.0
- Codebase: ~6,475 lines of Python code
- Prompt Templates: 79 Jinja2 modules across 10+ categories
- Python: 3.12, 3.13, 3.14
- Package: `strix-agent` on PyPI
- License: Apache 2.0

## Development Commands

```bash
# Install development environment
make setup-dev           # Install deps + pre-commit hooks

# Run Strix locally
poetry run strix --target ./app-directory
poetry run strix --target https://github.com/org/repo
poetry run strix -n -t ./app  # Non-interactive mode
poetry run strix --target ./app --scan-mode deep  # Deep scan

# Code quality
make format              # Format with ruff
make lint                # Lint with ruff + pylint
make type-check          # Type check with mypy + pyright
make security            # Security scan with bandit
make check-all           # Run all checks

# Testing
make test                # Run tests
make test-cov            # Run tests with coverage
poetry run pytest tests/tools/test_argument_parser.py -v  # Run single test file
poetry run pytest -k "test_name" -v  # Run specific test by name

# Cleanup
make clean               # Remove cache files
```

## Architecture

### Core Components

**Agent System** (`strix/agents/`)
- `BaseAgent` - Abstract agent with the main loop, LLM interaction, and state management. Uses metaclass `AgentMeta` to auto-configure Jinja templates per agent.
- `StrixAgent` - Main security testing agent that orchestrates scans (max 300 iterations). Inherits from BaseAgent.
- `VerificationAgent` - Spawned to verify vulnerability findings using two-phase verification (max 50 iterations):
  - Phase 1 (Reproducibility): Reproduces exact reported behavior with 3+ consecutive attempts
  - Phase 2 (Validity): Designs independent control tests using vulnerability type specifications
- `AgentState` - Pydantic model tracking agent state (messages, iteration count, sandbox info, errors, actions).
- Agent graph tracks parent-child relationships for multi-agent coordination via `agents_graph/` tool.

**Tool System** (`strix/tools/`)
- Tools are registered via `@register_tool` decorator from `registry.py`
- Each tool module has `*_actions.py` (implementation) and `*_schema.xml` (LLM-facing schema)
- Tools have two execution flags:
  - `sandbox_execution=True/False` - Run inside/outside Docker
  - `parallelizable=True/False` - Can run concurrently with other parallelizable tools

| Tool | Sandbox | Parallelizable | Purpose |
|------|---------|----------------|---------|
| `browser/` | True | False | Playwright-based web automation |
| `terminal/` | True | False | Shell command execution |
| `python/` | True | False | Python code execution |
| `file_edit/` | True | False | File reading/editing |
| `proxy/` | True | True | Caido HTTP proxy interception |
| `web_search/` | False | True | Perplexity API web search |
| `reporting/` | False | False | Vulnerability report creation |
| `agents_graph/` | False | True | Multi-agent coordination |
| `thinking/` | False | True | Internal reasoning |
| `notes/` | False | True | Note-taking during scan |
| `todo/` | False | True | Task management |
| `finish/` | False | False | Scan/agent completion |

**Runtime** (`strix/runtime/`)
- `DockerRuntime` - Manages Docker containers for sandboxed execution
- `tool_server.py` - FastAPI server running inside containers that executes tools
- Sandbox image: `ghcr.io/usestrix/strix-sandbox:0.1.10`
- Container capabilities: `NET_ADMIN`, `NET_RAW` for network control
- Token-based authentication: Bearer tokens via `secrets.token_urlsafe(32)`
- Tool server endpoints: `/execute`, `/register_agent`, `/health`
- Multiprocess architecture: Each agent gets dedicated worker process inside container

**LLM Integration** (`strix/llm/`)
- `LLM` class wraps LiteLLM for model interactions
- `LLMConfig` - Configuration for model, prompt caching, timeout, scan mode, prompt modules (max 5)
- `memory_compressor.py` - Handles conversation memory management:
  - Keeps 15 most recent messages intact
  - Summarizes older messages in 10-message chunks when exceeding 90K tokens
  - Limits images to 3 most recent for context
- `request_queue.py` - Thread-safe queuing with rate limiting and retry logic (tenacity)
- Prompt caching: Anthropic-specific ephemeral cache with 10-message intervals
- Model-specific handling for reasoning models (o1, grok, deepseek-r1) and vision models
- `RequestStats` tracks: input/output/cached tokens, cost, requests, failed requests
- Supports any LiteLLM-compatible provider (OpenAI, Anthropic, local models)

**Prompt System** (`strix/prompts/`)
- 79 Jinja2 templates organized by category (max 5 modules loaded per agent):
  - `vulnerabilities/` (25 templates) - IDOR, XSS, SQLi, CSRF, auth bypass, SSTI, SSRF, XXE, RCE, etc.
  - `verification_types/` (25 templates) - Verification-specific guidance mirroring vulnerabilities
  - `cloud/` (7 templates) - AWS, Azure, GCP security testing, IAM, credentials
  - `kubernetes/` (6 templates) - RBAC, secrets, workload escape, service accounts
  - `frameworks/` (2 templates) - FastAPI, Next.js specific testing
  - `technologies/` (2 templates) - Firebase/Firestore, Supabase
  - `reconnaissance/` (3 templates) - Enumeration and information gathering
  - `protocols/` (1 template) - GraphQL testing
  - `scan_modes/` (3 templates) - quick, standard, deep configurations
  - `coordination/` (2 templates) - Root agent and verification prompts
  - `custom/` - Community-contributed modules
- Modules loaded dynamically via `load_prompt_modules()` based on `LLMConfig.prompt_modules`
- `root_agent.jinja` is the main system prompt for the primary agent

**Interface** (`strix/interface/`)
- `main.py` - CLI entry point, argument parsing, Docker setup, LLM warmup
- `tui.py` - Textual-based interactive UI with dashboard, agent monitor, log viewer
- `cli.py` - Non-interactive headless mode for CI/CD integration
- `utils.py` - Helper functions:
  - `infer_target_type()` - Auto-detect target type (URL, repo, local code, IP)
  - `clone_repository()` - Git repo cloning with progress
  - `collect_local_sources()` - Local codebase gathering
  - Docker connection utilities and live statistics display
- `tool_components/` - 13 UI renderers for each tool type

**Telemetry** (`strix/telemetry/`)
- `tracer.py` - Global tracing for execution monitoring
- Tracks: agents, tool executions, messages, vulnerabilities
- Manages run directories (`strix_runs/<run_name>/`)
- Callbacks for real-time vulnerability notifications
- Statistics aggregation (tokens, cost, execution time)

### Multi-Agent Coordination

Strix supports hierarchical agent delegation:
- Parent agents can spawn child agents for specialized tasks via `spawn_agent` tool
- Agents communicate via message queues with `read` flag tracking
- Agent graph tracks parent-child relationships (`_agent_graph`, `_agent_instances`)
- Shared resources: `/workspace` directory, proxy history
- Inter-agent messaging with waiting state management (600-second auto-resume timeout)
- Each child agent runs in its own thread with full tool access

### Scan Modes

Three depth configurations available via `--scan-mode`:
- `quick` - Basic reconnaissance and common vulnerability checks
- `standard` - Balanced depth and coverage (default)
- `deep` - Exhaustive multi-phase testing:
  - Phase 1: Exhaustive reconnaissance and mapping
  - Phase 2: Deep business logic analysis
  - Phase 3: Comprehensive attack surface testing
  - Phase 4: Vulnerability chaining and pivot attacks
  - Phase 5: Persistent testing (2000+ steps minimum)
  - Phase 6: Thorough reporting

### Data Flow

1. User invokes `strix --target <target>`
2. `main.py` validates environment, pulls Docker image if needed, warms up LLM
3. `DockerRuntime.create_sandbox()` starts container with tool server
4. `StrixAgent.execute_scan()` builds task description and calls `agent_loop()`
5. Agent iterates: LLM generates response with tool calls -> tools executed (parallel/sequential) -> results returned to LLM
6. Vulnerability reports enter `pending_verification` -> `VerificationAgent` spawns to verify
7. Verified reports finalized; false positives rejected
8. Results saved to `strix_runs/<run-name>/`

### Environment Variables

```bash
# Required
STRIX_LLM                       # Model name (e.g., "openai/gpt-5", "anthropic/claude-sonnet-4-5")

# LLM Configuration
LLM_API_KEY                     # API key for LLM provider
LLM_API_BASE                    # Custom API base for local models (Ollama, LMStudio)
LLM_TIMEOUT                     # Request timeout in seconds (default: 300)
LLM_RATE_LIMIT_DELAY            # Delay between LLM requests
LLM_RATE_LIMIT_CONCURRENT       # Max concurrent LLM requests

# Optional Features
PERPLEXITY_API_KEY              # For web search capabilities
STRIX_DISABLE_BROWSER           # Disable browser tool

# Docker/Sandbox
STRIX_IMAGE                     # Custom sandbox image (default: ghcr.io/usestrix/strix-sandbox:0.1.10)
STRIX_SANDBOX_MODE              # Set to "true" when running inside sandbox container
STRIX_SANDBOX_EXECUTION_TIMEOUT # Tool execution timeout (default: 500s)
DOCKER_HOST                     # Docker daemon connection string
```

## Code Style

- Python 3.12+, strict type hints required
- 100 character line limit
- Ruff for formatting/linting, mypy + pyright for type checking
- Follow existing patterns in each module
- Tool schemas use XML format in `*_schema.xml` files

### Testing Patterns

- Tests mirror source structure in `tests/`
- Use pytest with asyncio auto mode
- Coverage reporting enabled by default
- Mock support via pytest-mock
- Test files: `test_*.py` naming convention

## Vulnerability Reporting

### Evidence Requirements

The `create_vulnerability_report` tool requires structured evidence to eliminate false positives:

```python
evidence = {
    # Required: Vulnerability classification
    "vulnerability_type": "idor",           # From registry (e.g., "idor", "xss", "sqli")
    "claim_assertion": str,                 # Specific security claim being made

    # Required: HTTP request/response pairs proving the vulnerability
    "primary_evidence": [
        {
            "method": "GET",
            "url": "https://example.com/api/users/999",
            "response_status": 200,
            "response_body_snippet": '{"id": 999, "email": "other@user.com"}',
            "timestamp": "2024-01-01T00:00:00Z"
        }
    ],

    # Required: Step-by-step reproduction instructions
    "reproduction_steps": [
        {
            "step_number": 1,
            "description": "Access another user's data via IDOR",
            "tool_used": "browser",
            "expected_result": "Should see other user's data",
            "actual_result": "Saw other user's email address"
        }
    ],

    # Required: The actual exploit payload
    "poc_payload": "GET /api/users/999",

    # Required: Affected URL
    "target_url": "https://example.com/api/users/999",

    # Optional fields
    "affected_parameter": "user_id",
    "baseline_state": "Normal user can only see their own data",
    "exploited_state": "User accessed another user's private data",

    # Reporter's control tests for verification
    "reporter_control_tests": [
        {
            "test_name": "Authorization check",
            "description": "Verified user 999 belongs to different account",
            "conclusion": "Confirmed cross-account data access"
        }
    ]
}
```

### Verification Workflow

1. **Pending Queue**: Reports enter `pending_verification` status, not immediately finalized
2. **Auto-Verification**: A `VerificationAgent` spawns to reproduce the finding:
   - Phase 1: Reproducibility - Can the behavior be reproduced? (3+ attempts)
   - Phase 2: Validity - Does the behavior actually prove the vulnerability?
3. **Finalization**: Only verified reports move to `vulnerability_reports`
4. **Rejection Tracking**: False positives are saved to `rejected_vulnerability_reports`

### Report States

- `pending_verification` - Initial state, awaiting verification
- `verified` - Reproduction confirmed, finalized as vulnerability
- `rejected` - Could not reproduce, marked as false positive

### Output Directories

- `strix_runs/<run>/vulnerability_reports/` - Verified vulnerabilities
- `strix_runs/<run>/pending_verification/` - Awaiting verification
- `strix_runs/<run>/rejected_false_positives/` - Rejected reports

### Prompt Module Structure

Vulnerability prompt modules in `strix/prompts/vulnerabilities/` include:

- `<llm_reasoning_errors>` - Common AI mistakes that cause false positives
- `<expanded_false_positives>` - Scenarios that should NOT be reported
- `<validation>` - Criteria for confirming a vulnerability
- `<false_positives>` - Quick reference for non-vulnerable scenarios

## Contributing Prompt Modules

Add `.jinja` files to appropriate category in `strix/prompts/`:
- `vulnerabilities/` - Attack-specific knowledge (IDOR, XSS, SQLi, etc.)
- `verification_types/` - Verification-specific guidance for each vulnerability type
- `frameworks/` - Framework-specific testing (FastAPI, Next.js)
- `technologies/` - Platform knowledge (Firebase, Supabase)
- `protocols/` - Protocol testing (GraphQL)
- `cloud/` - Cloud security (AWS, Azure, GCP)
- `kubernetes/` - Container orchestration security
- `reconnaissance/` - Information gathering techniques
- `scan_modes/` - Depth configurations (quick, standard, deep)
- `custom/` - Community contributions
