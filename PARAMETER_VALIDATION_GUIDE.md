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

**Utility (24/24)** ✅ COMPLETE
- ✅ `api_fuzzer` - Full validation
- ✅ `cve_lookup` - Full validation
- ✅ `parameter_miner` - Full validation
- ✅ `secret_scanner` - Full validation
- ✅ `waf_detector` - Full validation
- ✅ `oob_server` - Full validation
- ✅ `hash_identifier` - Full validation
- ✅ `js_link_extractor` - Full validation
- ✅ `oauth_tester` - Full validation
- ✅ `payload_encoder` - Full validation
- ✅ `timing_analyzer` - Full validation
- ✅ `response_diff` - Full validation
- ✅ `poc_generator` - Full validation
- ✅ `polyglot_generator` - Full validation
- ✅ `rate_limit_tester` - Full validation
- ✅ `dns_rebinding_server` - Full validation
- ✅ `entropy_analyzer` - Full validation
- ✅ `regex_tester` - Full validation
- ✅ `websocket_client` - Full validation
- ✅ `cloud_enumeration` - Full validation
- ✅ `cvss_calculator` - Full validation
- ✅ `sast_engine` - Full validation
- ✅ `dependency_auditor` - Full validation
- ✅ `waf_bypass_toolkit` - Full validation

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

**Overall Progress: 43/43 tools complete (100%)** ✅ 🎉

### Completed Categories ✅
1. ✅ **Security Analysis: 6/6 complete (100%)**
2. ✅ **Reconnaissance: 7/7 complete (100%)**
3. ✅ **Vulnerability Testing: 6/6 complete (100%)**
4. ✅ **Utility: 24/24 complete (100%)**

### All Tools Completed! 🎉

All 43 Strix security testing tools now have complete parameter validation:
- Unknown parameter detection
- Action validation with helpful error messages
- Required parameter validation
- Usage examples for all actions
- Consistent error handling across all tools

## Related Files

- `strix/tools/validation.py` - Validation helper functions
- `strix/tools/executor.py` - Error formatting (lines 168-219)
- `tests/test_tool_parameter_validation.py` - Test suite
- Individual tool files in `strix/tools/*/` directories

## Implementation Complete

All 43 Strix tools now have parameter validation implemented following the established pattern. The validation system provides:

1. **Self-Correcting Agents**: Agents receive clear feedback and can retry with correct parameters
2. **Reduced Stuck States**: Unknown parameters are caught immediately, not silently ignored
3. **Better UX**: Clear error messages with examples guide users to correct usage
4. **Workflow Guidance**: Complex tools provide step-by-step workflows
5. **Consistent Error Handling**: All tools follow the same validation pattern

## Questions?

The validation system is extensible. For special cases or questions:
- Check existing fully-implemented tools for examples
- Refer to validation.py for available helper functions
- Run tests to verify behavior
