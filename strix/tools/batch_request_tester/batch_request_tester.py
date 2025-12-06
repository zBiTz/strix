"""Batch request testing tool for race conditions and atomicity testing."""

import json
import time
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "test_race",
    "test_batch",
    "test_bulk_operations",
    "check_atomicity",
    "test_parallel",
]


@register_tool(sandbox_execution=True)
def batch_request_tester(
    action: ToolAction,
    target: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    payload: dict | None = None,
    payloads: list[dict] | None = None,
    headers: dict | None = None,
    concurrency: int | None = None,
    iterations: int | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Batch request testing tool for race conditions and atomicity.

    Args:
        action: The action to perform
        target: Target URL base
        endpoint: API endpoint path
        method: HTTP method
        payload: Single request payload
        payloads: Multiple payloads for batch testing
        headers: Request headers
        concurrency: Number of concurrent requests
        iterations: Number of test iterations

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "target", "endpoint", "method", "payload",
        "payloads", "headers", "concurrency", "iterations",
    }
    VALID_ACTIONS = [
        "test_race",
        "test_batch",
        "test_bulk_operations",
        "check_atomicity",
        "test_parallel",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "batch_request_tester"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "batch_request_tester"):
        return action_error

    if action == "test_race":
        if param_error := validate_required_param(target, "target", action, "batch_request_tester"):
            return param_error

        ep = endpoint or "/api/transfer"
        http_method = method or "POST"
        concurrent = concurrency or 10
        test_payload = payload or {"amount": 100, "to_account": "attacker"}

        return {
            "action": "test_race",
            "target": target,
            "endpoint": ep,
            "method": http_method,
            "concurrency": concurrent,
            "payload": test_payload,
            "description": "Race condition testing - send concurrent requests to exploit TOCTOU",
            "vulnerability_types": [
                "Double spending / duplicate transactions",
                "Coupon/reward code reuse",
                "Inventory overselling",
                "Vote/like manipulation",
                "Account balance race conditions",
            ],
            "python_example": f'''
import asyncio
import aiohttp
import json

async def send_request(session, url, payload, headers):
    async with session.post(url, json=payload, headers=headers) as response:
        return await response.json()

async def race_condition_test():
    url = "{target}{ep}"
    payload = {json.dumps(test_payload)}
    headers = {{"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}}

    async with aiohttp.ClientSession() as session:
        # Create {concurrent} concurrent requests
        tasks = [send_request(session, url, payload, headers) for _ in range({concurrent})]

        # Fire all at once
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        successes = [r for r in results if not isinstance(r, Exception)]
        print(f"Successful requests: {{len(successes)}}/{concurrent}")

        # Check for race condition indicators
        if len(successes) > 1:
            print("[!] POTENTIAL RACE CONDITION - Multiple requests succeeded!")

asyncio.run(race_condition_test())
''',
            "turbo_intruder_script": '''
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=False)

    for i in range(50):
        engine.queue(target.req, gate='race')

    engine.openGate('race')

def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
''',
            "indicators_of_success": [
                "Multiple 200 responses when only one should succeed",
                "Database shows duplicate entries",
                "Balance changed more than expected",
                "Multiple rewards/coupons applied",
            ],
            "mitigation_checks": [
                "Does the app use database transactions?",
                "Is there proper locking mechanism?",
                "Are there idempotency keys?",
                "Is there rate limiting per user?",
            ],
        }

    elif action == "test_batch":
        if param_error := validate_required_param(target, "target", action, "batch_request_tester"):
            return param_error

        ep = endpoint or "/api/batch"
        batch_payloads = payloads or [
            {"action": "read", "id": 1},
            {"action": "read", "id": 2},
            {"action": "update", "id": 1, "data": {"admin": True}},
        ]

        return {
            "action": "test_batch",
            "target": target,
            "endpoint": ep,
            "payloads": batch_payloads,
            "description": "Test batch API endpoints for authorization bypass and injection",
            "attack_vectors": [
                "Mix authorized and unauthorized actions in same batch",
                "Include admin actions with regular user token",
                "Test if batch bypasses per-request validation",
                "Check for different auth contexts within batch",
            ],
            "graphql_batch_example": f'''
# GraphQL Batch Query Attack
curl -X POST {target}/graphql \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer USER_TOKEN" \\
  -d '[
    {{"query": "query {{ user(id: 1) {{ email }} }}"}},
    {{"query": "mutation {{ updateUser(id: 1, role: \\"admin\\") {{ id }} }}"}},
    {{"query": "query {{ adminSettings {{ secretKey }} }}"}}
  ]'
''',
            "rest_batch_example": f'''
# REST Batch Request
curl -X POST {target}{ep} \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer USER_TOKEN" \\
  -d '{{
    "requests": [
      {{"method": "GET", "path": "/users/1"}},
      {{"method": "PUT", "path": "/users/1", "body": {{"role": "admin"}}}},
      {{"method": "GET", "path": "/admin/secrets"}}
    ]
  }}'
''',
            "test_cases": [
                {
                    "name": "Authorization bypass in batch",
                    "description": "Include admin endpoint in batch with user token",
                },
                {
                    "name": "BOLA in batch",
                    "description": "Access multiple user IDs in single batch",
                },
                {
                    "name": "Rate limit bypass",
                    "description": "Many operations in single batch to bypass limits",
                },
            ],
        }

    elif action == "test_bulk_operations":
        if param_error := validate_required_param(target, "target", action, "batch_request_tester"):
            return param_error

        ep = endpoint or "/api/users/bulk"

        return {
            "action": "test_bulk_operations",
            "target": target,
            "endpoint": ep,
            "description": "Test bulk operations for injection and authorization issues",
            "attack_scenarios": {
                "bulk_update_injection": {
                    "description": "Inject unauthorized IDs in bulk update",
                    "payload": {
                        "ids": [1, 2, 3, 999],  # 999 is admin user
                        "update": {"status": "disabled"}
                    },
                },
                "bulk_delete_idor": {
                    "description": "Delete resources belonging to other users",
                    "payload": {
                        "ids": [100, 101, 102],  # Other users' resources
                    },
                },
                "bulk_create_mass_assignment": {
                    "description": "Mass create with elevated privileges",
                    "payload": {
                        "users": [
                            {"email": "test1@test.com", "role": "admin"},
                            {"email": "test2@test.com", "role": "admin"},
                        ]
                    },
                },
            },
            "curl_examples": {
                "bulk_update": f'''
curl -X PUT {target}{ep}/update \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer TOKEN" \\
  -d '{{"ids": [1, 2, 3, 999], "data": {{"role": "user"}}}}'
''',
                "bulk_delete": f'''
curl -X DELETE {target}{ep}/delete \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer TOKEN" \\
  -d '{{"ids": [100, 101, 102]}}'
''',
            },
            "validation_checks": [
                "Does bulk endpoint verify ownership of all IDs?",
                "Is there a limit on bulk operation size?",
                "Are individual item authorizations checked?",
                "Can bulk operations bypass rate limits?",
            ],
        }

    elif action == "check_atomicity":
        if param_error := validate_required_param(target, "target", action, "batch_request_tester"):
            return param_error

        ep = endpoint or "/api/transaction"
        test_payload = payload or {
            "operations": [
                {"type": "debit", "account": "A", "amount": 100},
                {"type": "credit", "account": "B", "amount": 100},
            ]
        }

        return {
            "action": "check_atomicity",
            "target": target,
            "endpoint": ep,
            "payload": test_payload,
            "description": "Test if multi-step operations are atomic",
            "test_methodology": [
                "1. Send request with multiple operations",
                "2. Force failure in middle operation",
                "3. Check if partial changes were committed",
                "4. Verify rollback behavior",
            ],
            "atomicity_attacks": {
                "partial_failure": {
                    "description": "Make second operation fail to check rollback",
                    "payload": {
                        "operations": [
                            {"type": "debit", "account": "A", "amount": 100},
                            {"type": "credit", "account": "INVALID", "amount": 100},
                        ]
                    },
                },
                "timeout_attack": {
                    "description": "Cause timeout between operations",
                    "method": "Use slow network or intercept to delay",
                },
                "concurrent_modification": {
                    "description": "Modify same resource during transaction",
                    "method": "Race condition with separate request",
                },
            },
            "python_test": f'''
import requests
import time

# Test 1: Partial failure
response = requests.post(
    "{target}{ep}",
    json={{
        "operations": [
            {{"type": "debit", "account": "user1", "amount": 100}},
            {{"type": "credit", "account": "NONEXISTENT", "amount": 100}}
        ]
    }},
    headers={{"Authorization": "Bearer TOKEN"}}
)

# Check if first operation was rolled back
balance = requests.get("{target}/api/accounts/user1").json()
print(f"Balance after failed transaction: {{balance}}")

# If balance was debited but credit failed = NOT ATOMIC!
''',
            "indicators_of_non_atomicity": [
                "Partial state changes on error",
                "Inconsistent data after failures",
                "Missing rollback on timeout",
                "Race conditions possible between steps",
            ],
        }

    elif action == "test_parallel":
        if param_error := validate_required_param(target, "target", action, "batch_request_tester"):
            return param_error

        concurrent = concurrency or 20
        iter_count = iterations or 5
        http_method = method or "POST"
        test_payload = payload or {"action": "increment"}

        return {
            "action": "test_parallel",
            "target": target,
            "concurrency": concurrent,
            "iterations": iter_count,
            "description": "Parallel request testing for concurrency issues",
            "test_scenarios": [
                {
                    "name": "Counter increment race",
                    "description": f"Send {concurrent} parallel increment requests",
                    "expected": f"Counter should increase by {concurrent}",
                    "vuln_indicator": "Counter increases by less (lost updates)",
                },
                {
                    "name": "Inventory race",
                    "description": "Parallel purchase of limited item",
                    "expected": "Only available quantity sold",
                    "vuln_indicator": "Oversold (negative inventory)",
                },
                {
                    "name": "Token generation race",
                    "description": "Parallel token generation",
                    "expected": "Unique tokens per request",
                    "vuln_indicator": "Duplicate tokens generated",
                },
            ],
            "golang_test": f'''
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
    "sync"
)

func main() {{
    var wg sync.WaitGroup
    url := "{target}"
    payload := {json.dumps(test_payload)}

    for i := 0; i < {concurrent}; i++ {{
        wg.Add(1)
        go func() {{
            defer wg.Done()
            body, _ := json.Marshal(payload)
            http.Post(url, "application/json", bytes.NewBuffer(body))
        }}()
    }}

    wg.Wait()
}}
''',
            "artillery_config": f'''
# artillery.yml - Load testing config
config:
  target: "{target}"
  phases:
    - duration: 10
      arrivalRate: {concurrent}

scenarios:
  - flow:
      - post:
          url: "/"
          json: {json.dumps(test_payload)}
''',
            "analysis_steps": [
                "Record state before test",
                "Run parallel requests",
                "Record state after test",
                "Compare expected vs actual changes",
                "Look for lost updates or duplicate processing",
            ],
        }

    return generate_usage_hint("batch_request_tester", VALID_ACTIONS)
