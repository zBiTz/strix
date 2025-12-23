# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Strix is an open-source AI-powered security testing tool that uses autonomous agents to perform penetration testing. It runs target applications in Docker sandbox containers and uses LLMs to orchestrate security testing through a multi-agent architecture.

## Development Commands

```bash
# Install development environment
make setup-dev           # Install deps + pre-commit hooks

# Run Strix locally
poetry run strix --target ./app-directory
poetry run strix --target https://github.com/org/repo
poetry run strix -n -t ./app  # Non-interactive mode

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
- `StrixAgent` - Main security testing agent that orchestrates scans. Inherits from BaseAgent.
- `AgentState` - Pydantic model tracking agent state (messages, iteration count, sandbox info).

**Tool System** (`strix/tools/`)
- Tools are registered via `@register_tool` decorator from `registry.py`
- Each tool module has `*_actions.py` (implementation) and `*_schema.xml` (LLM-facing schema)
- Tools can be marked `sandbox_execution=True/False` to run inside/outside Docker
- Tool modules: `browser/`, `proxy/`, `terminal/`, `python/`, `file_edit/`, `notes/`, `reporting/`, `web_search/`, `thinking/`, `todo/`, `finish/`, `agents_graph/`

**Runtime** (`strix/runtime/`)
- `DockerRuntime` - Manages Docker containers for sandboxed execution
- `tool_server.py` - FastAPI server running inside containers that executes tools
- Sandbox image: `ghcr.io/usestrix/strix-sandbox`

**LLM Integration** (`strix/llm/`)
- `LLM` class wraps LiteLLM for model interactions
- `LLMConfig` - Configuration for model, prompt caching, timeout, scan mode
- `memory_compressor.py` - Handles conversation memory management
- Supports any LiteLLM-compatible provider (OpenAI, Anthropic, local models)

**Prompt System** (`strix/prompts/`)
- Jinja2 templates organized by category: `vulnerabilities/`, `frameworks/`, `technologies/`, `protocols/`, `scan_modes/`, `coordination/`
- Modules loaded dynamically via `load_prompt_modules()` based on `LLMConfig.prompt_modules`
- `root_agent.jinja` is the main system prompt for the primary agent

**Interface** (`strix/interface/`)
- `main.py` - CLI entry point, argument parsing, Docker setup
- `tui.py` - Textual-based interactive UI
- `cli.py` - Non-interactive headless mode
- `tool_components/` - UI renderers for each tool type

### Data Flow

1. User invokes `strix --target <target>`
2. `main.py` validates environment, pulls Docker image if needed, warms up LLM
3. `DockerRuntime.create_sandbox()` starts container with tool server
4. `StrixAgent.execute_scan()` builds task description and calls `agent_loop()`
5. Agent iterates: LLM generates response with tool calls -> tools executed in sandbox -> results returned to LLM
6. Results saved to `strix_runs/<run-name>/`

### Environment Variables

```bash
STRIX_LLM           # Required: Model name (e.g., "openai/gpt-5", "anthropic/claude-sonnet-4-5")
LLM_API_KEY         # API key for LLM provider
LLM_API_BASE        # Custom API base for local models (Ollama, LMStudio)
PERPLEXITY_API_KEY  # For web search capabilities
LLM_TIMEOUT         # Request timeout in seconds (default: 300)
STRIX_SANDBOX_MODE  # Set to "true" when running inside sandbox container
```

## Code Style

- Python 3.12+, strict type hints required
- 100 character line limit
- Ruff for formatting/linting, mypy + pyright for type checking
- Follow existing patterns in each module
- Tool schemas use XML format in `*_schema.xml` files

## Vulnerability Reporting

### Evidence Requirements

The `create_vulnerability_report` tool requires structured evidence to eliminate false positives:

```python
evidence = {
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
    "exploited_state": "User accessed another user's private data"
}
```

### Verification Workflow

1. **Pending Queue**: Reports enter `pending_verification` status, not immediately finalized
2. **Auto-Verification**: A `VerificationAgent` spawns to reproduce the finding
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
- `frameworks/` - Framework-specific testing (FastAPI, Next.js)
- `technologies/` - Platform knowledge (Firebase, Supabase)
- `protocols/` - Protocol testing (GraphQL)
- `scan_modes/` - Depth configurations (quick, standard, deep)
