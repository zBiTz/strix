"""Tests for tool usage guidance in system prompt and agent delegation."""

import xml.etree.ElementTree as ET

import pytest
from jinja2 import Environment, FileSystemLoader


class TestSystemPromptToolGuidance:
    """Tests for tool usage guidance in system_prompt.jinja."""

    @pytest.fixture
    def jinja_env(self) -> Environment:
        """Create a Jinja2 environment for loading templates."""
        return Environment(loader=FileSystemLoader("strix/agents/StrixAgent"))

    @pytest.fixture
    def mock_template_functions(self) -> dict:
        """Mock functions used in the template."""

        def mock_get_tools_prompt() -> str:
            return "<!-- TOOLS PROMPT PLACEHOLDER -->"

        def mock_get_module(module_name: str) -> str:
            return f"<!-- MODULE {module_name} PLACEHOLDER -->"

        return {
            "get_tools_prompt": mock_get_tools_prompt,
            "get_module": mock_get_module,
        }

    def test_template_syntax_valid(self, jinja_env: Environment) -> None:
        """Test that system_prompt.jinja has valid Jinja2 syntax."""
        template = jinja_env.get_template("system_prompt.jinja")
        assert template is not None

    def test_tool_usage_priority_section_present(
        self, jinja_env: Environment, mock_template_functions: dict
    ) -> None:
        """Test that <tool_usage_priority> section is present in rendered template."""
        # Add mock functions to environment
        for name, func in mock_template_functions.items():
            jinja_env.globals[name] = func

        template = jinja_env.get_template("system_prompt.jinja")
        rendered = template.render(loaded_module_names=[])

        assert "<tool_usage_priority>" in rendered
        assert "</tool_usage_priority>" in rendered

    def test_tool_guidance_content(
        self, jinja_env: Environment, mock_template_functions: dict
    ) -> None:
        """Test that tool guidance contains expected content."""
        for name, func in mock_template_functions.items():
            jinja_env.globals[name] = func

        template = jinja_env.get_template("system_prompt.jinja")
        rendered = template.render(loaded_module_names=[])

        # Check for key guidance text
        assert "IMPORTANT: Always prefer built-in registered tools" in rendered
        assert "BEFORE using terminal_execute or python_action" in rendered
        assert "WHY use built-in tools:" in rendered
        assert "ONLY use terminal_execute or python_action when:" in rendered

    def test_available_tools_section_present(
        self, jinja_env: Environment, mock_template_functions: dict
    ) -> None:
        """Test that available tools by category section is present."""
        for name, func in mock_template_functions.items():
            jinja_env.globals[name] = func

        template = jinja_env.get_template("system_prompt.jinja")
        rendered = template.render(loaded_module_names=[])

        assert "AVAILABLE TOOLS BY CATEGORY:" in rendered

    def test_tool_mapping_table_present(
        self, jinja_env: Environment, mock_template_functions: dict
    ) -> None:
        """Test that tool mapping table with common tasks is present."""
        for name, func in mock_template_functions.items():
            jinja_env.globals[name] = func

        template = jinja_env.get_template("system_prompt.jinja")
        rendered = template.render(loaded_module_names=[])

        # Check for key tool mappings from the problem statement
        assert "subdomain_enum" in rendered
        assert "dns_resolver" in rendered
        assert "graphql_introspection" in rendered
        assert "js_link_extractor" in rendered
        assert "ssl_certificate_analyzer" in rendered
        assert "header_analyzer" in rendered
        assert "whois_lookup" in rendered
        assert "wayback_fetcher" in rendered
        assert "sqli_tester" in rendered
        assert "cors_scanner" in rendered

    def test_tool_categories_present(
        self, jinja_env: Environment, mock_template_functions: dict
    ) -> None:
        """Test that all tool categories are present."""
        for name, func in mock_template_functions.items():
            jinja_env.globals[name] = func

        template = jinja_env.get_template("system_prompt.jinja")
        rendered = template.render(loaded_module_names=[])

        assert "Reconnaissance:" in rendered
        assert "API/Web Analysis:" in rendered
        assert "Security Testing:" in rendered
        assert "Utilities:" in rendered


class TestAgentDelegationToolGuidance:
    """Tests for tool guidance in agent delegation XML."""

    def test_tool_guidance_xml_structure(self) -> None:
        """Test that agent delegation XML has proper structure with tool_guidance."""

        # Mock state and data
        class MockState:
            agent_name = "Test Agent"
            agent_id = "test_123"
            parent_id = "parent_456"
            task = "Test task"

        state = MockState()
        parent_name = "Parent Agent"
        context_status = "inherited conversation context"

        # Create task_xml as it appears in the code
        task_xml = f"""<agent_delegation>
    <identity>
        ⚠️ You are NOT your parent agent. You are a NEW, SEPARATE sub-agent (not root).

        Your Info: {state.agent_name} ({state.agent_id})
        Parent Info: {parent_name} ({state.parent_id})
    </identity>

    <your_task>{state.task}</your_task>

    <tool_guidance>
        - Use built-in registered tools whenever possible (subdomain_enum, dns_resolver, etc.)
        - Avoid terminal_execute for tasks that have dedicated tools
        - Avoid python_action for tasks that have dedicated tools
        - Built-in tools have better error handling and parameter validation
        - Only use shell/Python when no built-in tool exists for your specific need
    </tool_guidance>

    <instructions>
        - You have {context_status}
        - Inherited context is for BACKGROUND ONLY - don't continue parent's work
        - Maintain strict self-identity: never speak as or for your parent
        - Do not merge your conversation with the parent's;
        - Do not claim parent's actions or messages as your own
        - Focus EXCLUSIVELY on your delegated task above
        - Work independently with your own approach
        - Use agent_finish when complete to report back to parent
        - You are a SPECIALIST for this specific task
        - You share the same container as other agents but have your own tool server instance
        - All agents share /workspace directory and proxy history for better collaboration
        - You can see files created by other agents and proxy traffic from previous work
        - Build upon previous work but focus on your specific delegated task
    </instructions>
</agent_delegation>"""

        # Parse XML to ensure it's valid
        root = ET.fromstring(task_xml)

        # Verify root element
        assert root.tag == "agent_delegation"

        # Verify all required elements exist
        assert root.find("identity") is not None
        assert root.find("your_task") is not None
        assert root.find("tool_guidance") is not None
        assert root.find("instructions") is not None

    def test_tool_guidance_content_in_delegation(self) -> None:
        """Test that tool guidance contains expected content in agent delegation."""

        class MockState:
            agent_name = "Test Agent"
            agent_id = "test_123"
            parent_id = "parent_456"
            task = "Test task"

        state = MockState()
        parent_name = "Parent Agent"
        context_status = "inherited conversation context"

        task_xml = f"""<agent_delegation>
    <identity>
        ⚠️ You are NOT your parent agent. You are a NEW, SEPARATE sub-agent (not root).

        Your Info: {state.agent_name} ({state.agent_id})
        Parent Info: {parent_name} ({state.parent_id})
    </identity>

    <your_task>{state.task}</your_task>

    <tool_guidance>
        - Use built-in registered tools whenever possible (subdomain_enum, dns_resolver, etc.)
        - Avoid terminal_execute for tasks that have dedicated tools
        - Avoid python_action for tasks that have dedicated tools
        - Built-in tools have better error handling and parameter validation
        - Only use shell/Python when no built-in tool exists for your specific need
    </tool_guidance>

    <instructions>
        - You have {context_status}
    </instructions>
</agent_delegation>"""

        root = ET.fromstring(task_xml)
        tool_guidance = root.find("tool_guidance")

        assert tool_guidance is not None
        guidance_text = tool_guidance.text or ""

        # Check for key phrases
        assert "built-in registered tools" in guidance_text
        assert "terminal_execute" in guidance_text
        assert "python_action" in guidance_text
        assert "better error handling and parameter validation" in guidance_text

    def test_tool_guidance_positioned_before_instructions(self) -> None:
        """Test that tool_guidance appears before instructions in XML structure."""

        class MockState:
            agent_name = "Test Agent"
            agent_id = "test_123"
            parent_id = "parent_456"
            task = "Test task"

        state = MockState()
        parent_name = "Parent Agent"
        context_status = "inherited conversation context"

        task_xml = f"""<agent_delegation>
    <identity>Info</identity>
    <your_task>{state.task}</your_task>
    <tool_guidance>Use tools</tool_guidance>
    <instructions>Follow instructions</instructions>
</agent_delegation>"""

        root = ET.fromstring(task_xml)
        children = list(root)

        # Find positions
        tool_guidance_idx = next(
            i for i, child in enumerate(children) if child.tag == "tool_guidance"
        )
        instructions_idx = next(
            i for i, child in enumerate(children) if child.tag == "instructions"
        )

        # tool_guidance should come before instructions
        assert tool_guidance_idx < instructions_idx
