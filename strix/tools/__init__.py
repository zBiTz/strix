import os

from .executor import (
    execute_tool,
    execute_tool_invocation,
    execute_tool_with_validation,
    extract_screenshot_from_result,
    process_tool_invocations,
    remove_screenshot_from_result,
    validate_tool_availability,
)
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"

HAS_PERPLEXITY_API = bool(os.getenv("PERPLEXITY_API_KEY"))

if not SANDBOX_MODE:
    from .agents_graph import *  # noqa: F403
    from .api_fuzzer import *  # noqa: F403
    from .browser import *  # noqa: F403
    from .cors_scanner import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .finish import *  # noqa: F403
    from .graphql_introspection import *  # noqa: F403
    from .hash_identifier import *  # noqa: F403
    from .header_analyzer import *  # noqa: F403
    from .js_link_extractor import *  # noqa: F403

    # Security testing tools
    from .jwt_analyzer import *  # noqa: F403
    from .notes import *  # noqa: F403
    from .oauth_tester import *  # noqa: F403
    from .parameter_miner import *  # noqa: F403
    from .payload_encoder import *  # noqa: F403
    from .poc_generator import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .reporting import *  # noqa: F403
    from .request_logger import *  # noqa: F403

    # New security testing tools (batch 2)
    from .response_diff import *  # noqa: F403
    from .secret_scanner import *  # noqa: F403
    from .subdomain_enum import *  # noqa: F403
    from .tech_fingerprinter import *  # noqa: F403
    from .terminal import *  # noqa: F403
    from .thinking import *  # noqa: F403
    from .timing_analyzer import *  # noqa: F403
    from .websocket_client import *  # noqa: F403

    # New security testing tools (batch 3) - Reconnaissance
    from .asn_lookup import *  # noqa: F403
    from .dns_resolver import *  # noqa: F403
    from .google_dorker import *  # noqa: F403
    from .ssl_certificate_analyzer import *  # noqa: F403
    from .wayback_fetcher import *  # noqa: F403
    from .whois_lookup import *  # noqa: F403

    # New security testing tools (batch 3) - Testing
    from .cookie_analyzer import *  # noqa: F403
    from .rate_limit_tester import *  # noqa: F403
    from .regex_tester import *  # noqa: F403
    from .sqli_tester import *  # noqa: F403

    # New security testing tools (batch 4) - Active Testing
    from .command_injection_tester import *  # noqa: F403
    from .http_method_tester import *  # noqa: F403
    from .ssrf_tester import *  # noqa: F403
    from .ssti_tester import *  # noqa: F403
    from .waf_detector import *  # noqa: F403
    from .xxe_tester import *  # noqa: F403

    # New security testing tools (batch 5) - Specialized Tools
    from .cve_lookup import *  # noqa: F403
    from .cvss_calculator import *  # noqa: F403
    from .entropy_analyzer import *  # noqa: F403
    from .polyglot_generator import *  # noqa: F403

    if HAS_PERPLEXITY_API:
        from .web_search import *  # noqa: F403
else:
    from .api_fuzzer import *  # noqa: F403
    from .browser import *  # noqa: F403
    from .cors_scanner import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .graphql_introspection import *  # noqa: F403
    from .hash_identifier import *  # noqa: F403
    from .header_analyzer import *  # noqa: F403
    from .js_link_extractor import *  # noqa: F403

    # Security testing tools (also available in sandbox mode)
    from .jwt_analyzer import *  # noqa: F403
    from .notes import *  # noqa: F403
    from .oauth_tester import *  # noqa: F403
    from .parameter_miner import *  # noqa: F403
    from .payload_encoder import *  # noqa: F403
    from .poc_generator import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .request_logger import *  # noqa: F403

    # New security testing tools (batch 2) - also available in sandbox mode
    from .response_diff import *  # noqa: F403
    from .secret_scanner import *  # noqa: F403
    from .subdomain_enum import *  # noqa: F403
    from .tech_fingerprinter import *  # noqa: F403
    from .terminal import *  # noqa: F403
    from .timing_analyzer import *  # noqa: F403
    from .websocket_client import *  # noqa: F403

    # New security testing tools (batch 3) - also available in sandbox mode
    from .asn_lookup import *  # noqa: F403
    from .dns_resolver import *  # noqa: F403
    from .google_dorker import *  # noqa: F403
    from .ssl_certificate_analyzer import *  # noqa: F403
    from .wayback_fetcher import *  # noqa: F403
    from .whois_lookup import *  # noqa: F403

    # New testing tools (batch 3) - also available in sandbox mode
    from .cookie_analyzer import *  # noqa: F403
    from .rate_limit_tester import *  # noqa: F403
    from .regex_tester import *  # noqa: F403
    from .sqli_tester import *  # noqa: F403

    # New security testing tools (batch 4) - also available in sandbox mode
    from .command_injection_tester import *  # noqa: F403
    from .http_method_tester import *  # noqa: F403
    from .ssrf_tester import *  # noqa: F403
    from .ssti_tester import *  # noqa: F403
    from .waf_detector import *  # noqa: F403
    from .xxe_tester import *  # noqa: F403

    # New security testing tools (batch 5) - also available in sandbox mode
    from .cve_lookup import *  # noqa: F403
    from .cvss_calculator import *  # noqa: F403
    from .entropy_analyzer import *  # noqa: F403
    from .polyglot_generator import *  # noqa: F403

__all__ = [
    "ImplementedInClientSideOnlyError",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "tools",
    "validate_tool_availability",
]
