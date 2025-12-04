# Parameter Validation Implementation Guide

## Overview

This guide documents the parameter validation system implemented to prevent agents from getting stuck when calling tools with incorrect or missing parameters.

## Problem Solved

Agents were getting stuck when:
- Using wrong parameter names (e.g., `target_url` instead of `headers`)
- Omitting required `action` parameters
- Passing URLs to tools that expect pre-fetched data
- Using invalid action values

## Solution Components

### 1. Validation Helper Module (`strix/tools/validation.py`)

Provides reusable validation functions:

- `validate_unknown_params()` - Detects invented/unknown parameters
- `validate_action_param()` - Validates action against allowed values
- `validate_required_param()` - Checks for missing required parameters
- `generate_usage_hint()` - Creates usage examples
- `generate_workflow_hint()` - Provides workflow guidance
- `detect_url_in_unknown_params()` - Detects URL-related mistakes
- `add_workflow_hint_for_url_params()` - Adds workflow hints for URL confusion

### 2. Enhanced Error Formatting (`strix/tools/executor.py`)

The executor now formats validation errors with:
- Clear error messages
- Helpful hints
- Usage examples (JSON formatted)
- Workflow steps (for complex tools)

### 3. Updated Tools

#### Fully Updated Tools (27 tools with complete validation logic) ✅

**Security Analysis (6/6)** ✅
- ✅ `header_analyzer` - With workflow hints for URL confusion
- ✅ `tech_fingerprinter` - With workflow hints
- ✅ `jwt_analyzer` - Full validation
- ✅ `cookie_analyzer` - Full validation
- ✅ `cors_scanner` - With workflow hints
- ✅ `graphql_introspection` - Full validation

**Reconnaissance (7/7)** ✅
- ✅ `subdomain_enum` - Full validation with examples
- ✅ `wayback_fetcher` - Detects 'query' parameter mistake
- ✅ `dns_resolver` - Full validation
- ✅ `asn_lookup` - Full validation
- ✅ `whois_lookup` - Full validation
- ✅ `google_dorker` - Full validation
- ✅ `ssl_certificate_analyzer` - Full validation

**Vulnerability Testing (6/6)** ✅
- ✅ `sqli_tester` - Full validation
- ✅ `ssti_tester` - Full validation
- ✅ `ssrf_tester` - Full validation
- ✅ `xxe_tester` - Full validation
- ✅ `command_injection_tester` - Full validation
- ✅ `http_method_tester` - Full validation

**Utility (8/24)** - IN PROGRESS
- ✅ `api_fuzzer` - Full validation
- ✅ `cve_lookup` - Full validation
- ✅ `parameter_miner` - Full validation
- ✅ `secret_scanner` - Full validation
- ✅ `waf_detector` - Full validation
- ✅ `oob_server` - Full validation
- ✅ `hash_identifier` - Full validation
- ✅ `js_link_extractor` - Full validation

#### Partially Updated Tools (8 utility tools with imports + **kwargs)

These tools have:
- ✅ Validation imports added
- ✅ `**kwargs` parameter to capture unknown params
- ⚠️ **NEED**: Validation logic implementation (follow pattern in guide)

**Utility Tools Needing Validation Logic (8 tools)**
1. `oauth_tester` - Has imports + **kwargs, needs validation
2. `payload_encoder` - Has imports + **kwargs, needs validation
3. `timing_analyzer` - Has imports + **kwargs, needs validation
4. `response_diff` - Has imports + **kwargs, needs validation
5. `poc_generator` - Has imports + **kwargs, needs validation
6. `polyglot_generator` - Has imports + **kwargs, needs validation
7. `rate_limit_tester` - Has imports + **kwargs, needs validation
8. `dns_rebinding_server` - Has imports + **kwargs, needs validation

#### Not Yet Updated (8 tools needing full implementation)

These tools need:
- ⚠️ Validation imports
- ⚠️ `**kwargs` parameter
- ⚠️ Validation logic

**Tools Needing Full Implementation (8 tools)**
1. `entropy_analyzer` - VALID_ACTIONS: ["analyze", "compare", "batch_analyze"]
2. `regex_tester` - Check file for actions
3. `websocket_client` - VALID_ACTIONS: ["connect_info", "generate_payloads", "test_origin", "generate_exploit"]
4. `cloud_enumeration` - VALID_ACTIONS: ["enumerate_s3", "enumerate_azure_blob", "enumerate_gcp_bucket", "generate_wordlist"]
5. `cvss_calculator` - VALID_ACTIONS: ["calculate_v3", "calculate_v4", "parse_vector"]
6. `sast_engine` - VALID_ACTIONS: ["scan_code", "scan_file", "list_rules"]
7. `dependency_auditor` - Check file for actions
8. `waf_bypass_toolkit` - Check file for actions

## Implementation Pattern

### Step 1: Add Imports

```python
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)
```

### Step 2: Add **kwargs Parameter

```python
@register_tool
def tool_name(
    action: ActionType,
    param1: str,
    param2: str | None = None,
    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
```

### Step 3: Add Validation Logic

Add this code right after the docstring, before the `try` block:

```python
@register_tool
def tool_name(
    action: ActionType,
    required_param: str,
    optional_param: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Tool documentation..."""
    
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "required_param", "optional_param"}
    VALID_ACTIONS = ["action1", "action2", "action3"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "tool_name")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("tool_name", "action1", {"required_param": "example_value"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "tool_name")
    if action_error:
        action_error["usage_examples"] = {
            "action1": "tool_name(action='action1', required_param='value')",
            "action2": "tool_name(action='action2', required_param='value')",
        }
        return action_error

    # Validate required parameters (for specific actions)
    if action == "action1":
        param_error = validate_required_param(required_param, "required_param", action, "tool_name")
        if param_error:
            param_error.update(
                generate_usage_hint("tool_name", action, {"required_param": "example_value"})
            )
            return param_error

    try:
        # Existing tool implementation...
```

### Step 4: Add Workflow Hints (for data analysis tools)

For tools that analyze pre-fetched data (headers, responses, etc.), add workflow hints:

```python
# Check for unknown parameters
unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "tool_name")
if unknown_error:
    unknown_params = list(kwargs.keys())
    # Detect common mistake of passing URL instead of data
    if detect_url_in_unknown_params(unknown_params):
        workflow_steps = [
            "1. Use send_request(method='GET', url='https://example.com') to fetch the page",
            "2. Extract data from the response",
            "3. Call tool_name(action='analyze', data={...extracted data...})",
        ]
        unknown_error = add_workflow_hint_for_url_params(unknown_error, workflow_steps)
    
    unknown_error.update(
        generate_usage_hint("tool_name", "analyze", {"data": {"key": "value"}})
    )
    return unknown_error
```

## Testing

### Unit Tests

Run the validation unit tests:

```bash
poetry run pytest tests/test_tool_parameter_validation.py -v
```

Current status: **26/26 tests passing** ✅

### Manual Testing

Test a tool with wrong parameters:

```python
from strix.tools.subdomain_enum.subdomain_enum import subdomain_enum

# Test unknown parameter
result = subdomain_enum(
    action='enumerate',
    domain='example.com',
    target_url='https://example.com'  # Wrong parameter
)
# Returns helpful error with valid parameters list

# Test invalid action
result = subdomain_enum(
    action='scan',  # Invalid
    domain='example.com'
)
# Returns error with list of valid actions and usage examples

# Test missing required parameter
result = subdomain_enum(
    action='enumerate',
    domain=''  # Empty/missing
)
# Returns error indicating domain is required with example
```

### Expected Error Format

Errors are formatted by the executor and include:

```xml
<tool_result>
<tool_name>subdomain_enum</tool_name>
<result>Error: Unknown parameter(s): ['target_url']. Valid parameters are: ['action', 'domain', 'subdomain', 'timeout', 'wordlist']

Hint: Did you mean one of the valid parameters listed above?

Example usage:
{
  "action": "enumerate",
  "domain": "example.com"
}
</result>
</tool_result>
```

## Benefits

1. **Self-Correcting Agents**: Agents receive clear feedback and can retry with correct parameters
2. **Reduced Stuck States**: Unknown parameters are caught immediately, not silently ignored
3. **Better UX**: Clear error messages with examples guide users to correct usage
4. **Workflow Guidance**: Complex tools provide step-by-step workflows
5. **Consistent Error Handling**: All tools follow the same validation pattern

## Completion Checklist

**Overall Progress: 27/43 tools complete (63%)** 🎯

### Completed Categories ✅
1. ✅ **Security Analysis: 6/6 complete (100%)**
2. ✅ **Reconnaissance: 7/7 complete (100%)**
3. ✅ **Vulnerability Testing: 6/6 complete (100%)**

### In Progress Categories 🚧
4. ⚠️ **Utility: 8/24 complete (33%)**
   - 8 tools need only validation logic (have imports + **kwargs)
   - 8 tools need full implementation (imports + **kwargs + validation)

### Remaining Work
**Priority 1: Add Validation Logic to 8 Utility Tools (Partially Updated)**
These tools already have imports and **kwargs, just need validation logic added:
1. `oauth_tester`
2. `payload_encoder`
3. `timing_analyzer`
4. `response_diff`
5. `poc_generator`
6. `polyglot_generator`
7. `rate_limit_tester`
8. `dns_rebinding_server`

**Priority 2: Full Implementation for 8 Tools (Not Yet Updated)**
These tools need imports, **kwargs, AND validation logic:
1. `entropy_analyzer`
2. `regex_tester`
3. `websocket_client`
4. `cloud_enumeration`
5. `cvss_calculator`
6. `sast_engine`
7. `dependency_auditor`
8. `waf_bypass_toolkit`

## Related Files

- `strix/tools/validation.py` - Validation helper functions
- `strix/tools/executor.py` - Error formatting (lines 168-219)
- `tests/test_tool_parameter_validation.py` - Test suite
- Individual tool files in `strix/tools/*/` directories

## Next Steps

For each partially updated tool:
1. Identify the Literal type for actions
2. List all valid parameters
3. Add validation logic using the pattern above
4. Add workflow hints if the tool analyzes pre-fetched data
5. Test manually with wrong parameters
6. Add integration tests if needed

## Questions?

The validation system is extensible. For special cases or questions:
- Check existing fully-implemented tools for examples
- Refer to validation.py for available helper functions
- Run tests to verify behavior
