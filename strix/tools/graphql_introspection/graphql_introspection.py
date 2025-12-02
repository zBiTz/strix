"""GraphQL Introspection tool for GraphQL security testing."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool


GraphQLAction = Literal["introspection_query", "parse_schema", "generate_queries", "security_analysis"]


# Standard GraphQL introspection query
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

# Simplified introspection query
SIMPLE_INTROSPECTION = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
"""


def _parse_type_ref(type_ref: dict[str, Any] | None) -> str:
    """Parse a GraphQL type reference to a string representation."""
    if type_ref is None:
        return "Unknown"

    kind = type_ref.get("kind", "")
    name = type_ref.get("name")
    of_type = type_ref.get("ofType")

    if kind == "NON_NULL":
        return f"{_parse_type_ref(of_type)}!"
    if kind == "LIST":
        return f"[{_parse_type_ref(of_type)}]"
    if name:
        return name
    return "Unknown"


def _extract_types(schema_data: dict[str, Any]) -> dict[str, Any]:
    """Extract and categorize types from introspection result."""
    types_data = schema_data.get("data", {}).get("__schema", {}).get("types", [])

    types: dict[str, list[dict[str, Any]]] = {
        "objects": [],
        "inputs": [],
        "enums": [],
        "interfaces": [],
        "scalars": [],
        "unions": [],
    }

    for t in types_data:
        name = t.get("name", "")
        kind = t.get("kind", "")

        # Skip internal types
        if name.startswith("__"):
            continue

        type_info: dict[str, Any] = {
            "name": name,
            "description": t.get("description"),
        }

        if kind == "OBJECT":
            type_info["fields"] = [
                {
                    "name": f.get("name"),
                    "type": _parse_type_ref(f.get("type")),
                    "args": [
                        {"name": a.get("name"), "type": _parse_type_ref(a.get("type"))}
                        for a in f.get("args", [])
                    ],
                }
                for f in t.get("fields", []) or []
            ]
            types["objects"].append(type_info)

        elif kind == "INPUT_OBJECT":
            type_info["fields"] = [
                {"name": f.get("name"), "type": _parse_type_ref(f.get("type"))}
                for f in t.get("inputFields", []) or []
            ]
            types["inputs"].append(type_info)

        elif kind == "ENUM":
            type_info["values"] = [v.get("name") for v in t.get("enumValues", []) or []]
            types["enums"].append(type_info)

        elif kind == "INTERFACE":
            types["interfaces"].append(type_info)

        elif kind == "SCALAR":
            types["scalars"].append(type_info)

        elif kind == "UNION":
            types["unions"].append(type_info)

    return types


def _generate_sample_queries(schema_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate sample queries based on schema."""
    schema = schema_data.get("data", {}).get("__schema", {})
    types_list = schema.get("types", [])

    # Find Query type
    query_type_name = schema.get("queryType", {}).get("name", "Query")
    mutation_type_name = schema.get("mutationType", {}).get("name") if schema.get("mutationType") else None

    queries: list[dict[str, Any]] = []

    for t in types_list:
        if t.get("name") == query_type_name:
            for field in t.get("fields", []) or []:
                field_name = field.get("name", "")
                field_type = _parse_type_ref(field.get("type"))
                args = field.get("args", [])

                # Build query
                if args:
                    args_str = ", ".join([f'${a["name"]}: {_parse_type_ref(a["type"])}' for a in args])
                    params_str = ", ".join([f'{a["name"]}: ${a["name"]}' for a in args])
                    query = f"query {field_name}Query({args_str}) {{ {field_name}({params_str}) {{ ... }} }}"
                else:
                    query = f"query {{ {field_name} {{ ... }} }}"

                queries.append({
                    "name": field_name,
                    "type": field_type,
                    "query": query,
                    "args": [{"name": a.get("name"), "type": _parse_type_ref(a.get("type"))} for a in args],
                    "category": "query",
                })

        if mutation_type_name and t.get("name") == mutation_type_name:
            for field in t.get("fields", []) or []:
                field_name = field.get("name", "")
                field_type = _parse_type_ref(field.get("type"))
                args = field.get("args", [])

                if args:
                    args_str = ", ".join([f'${a["name"]}: {_parse_type_ref(a["type"])}' for a in args])
                    params_str = ", ".join([f'{a["name"]}: ${a["name"]}' for a in args])
                    query = f"mutation {field_name}Mutation({args_str}) {{ {field_name}({params_str}) {{ ... }} }}"
                else:
                    query = f"mutation {{ {field_name} {{ ... }} }}"

                queries.append({
                    "name": field_name,
                    "type": field_type,
                    "query": query,
                    "args": [{"name": a.get("name"), "type": _parse_type_ref(a.get("type"))} for a in args],
                    "category": "mutation",
                })

    return queries


def _analyze_security(schema_data: dict[str, Any]) -> dict[str, Any]:
    """Analyze schema for security concerns."""
    issues: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []

    schema = schema_data.get("data", {}).get("__schema", {})
    types_list = schema.get("types", [])

    # Check for introspection (the fact we got here means it's enabled)
    issues.append({
        "severity": "medium",
        "issue": "Introspection enabled",
        "description": "GraphQL introspection is enabled, allowing schema discovery",
        "recommendation": "Disable introspection in production",
    })

    # Analyze types for security patterns
    for t in types_list:
        name = t.get("name", "")
        if name.startswith("__"):
            continue

        # Check for sensitive-looking types
        sensitive_patterns = ["admin", "internal", "private", "secret", "password", "token", "credential"]
        for pattern in sensitive_patterns:
            if pattern in name.lower():
                info.append({
                    "type": name,
                    "note": f"Type name contains '{pattern}' - may contain sensitive data",
                })

        # Check fields
        for field in t.get("fields", []) or []:
            field_name = field.get("name", "")
            for pattern in sensitive_patterns:
                if pattern in field_name.lower():
                    info.append({
                        "type": name,
                        "field": field_name,
                        "note": f"Field name contains '{pattern}' - check authorization",
                    })

    # Check for mutations that might be dangerous
    mutation_type_name = schema.get("mutationType", {}).get("name") if schema.get("mutationType") else None
    if mutation_type_name:
        for t in types_list:
            if t.get("name") == mutation_type_name:
                for field in t.get("fields", []) or []:
                    field_name = field.get("name", "")
                    dangerous_patterns = ["delete", "remove", "admin", "update", "create", "modify"]
                    for pattern in dangerous_patterns:
                        if pattern in field_name.lower():
                            info.append({
                                "mutation": field_name,
                                "note": f"Mutation '{field_name}' - verify authorization is required",
                            })

    return {
        "issues": issues,
        "security_info": info,
        "recommendations": [
            "Disable introspection in production environments",
            "Implement query depth limiting to prevent DoS",
            "Add query complexity analysis",
            "Ensure all sensitive queries/mutations require authentication",
            "Implement rate limiting on GraphQL endpoint",
            "Use persisted queries to limit attack surface",
        ],
    }


@register_tool
def graphql_introspection(
    action: GraphQLAction,
    schema_data: dict[str, Any] | None = None,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """GraphQL introspection and security analysis tool.

    This tool helps with GraphQL security testing by generating
    introspection queries, parsing schemas, and identifying
    security issues.

    Args:
        action: The GraphQL action to perform:
            - introspection_query: Get introspection query to send
            - parse_schema: Parse introspection result and extract types
            - generate_queries: Generate sample queries from schema
            - security_analysis: Analyze schema for security issues
        schema_data: Introspection query result (JSON) for parsing
        endpoint: GraphQL endpoint URL (for reference)

    Returns:
        Introspection queries, parsed schema, or security analysis
    """
    try:
        if action == "introspection_query":
            return {
                "full_query": INTROSPECTION_QUERY.strip(),
                "simple_query": SIMPLE_INTROSPECTION.strip(),
                "instructions": (
                    "Send the introspection query as a POST request to the GraphQL endpoint "
                    "with Content-Type: application/json. The query should be in the 'query' field."
                ),
                "curl_example": f"""curl -X POST \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{SIMPLE_INTROSPECTION.replace(chr(10), " ").replace('"', '\\"')}"}}' \\
  {endpoint or 'https://target.com/graphql'}""",
            }

        if action == "parse_schema":
            if not schema_data:
                return {"error": "schema_data parameter required for this action"}

            types = _extract_types(schema_data)

            return {
                "types": types,
                "summary": {
                    "objects": len(types["objects"]),
                    "inputs": len(types["inputs"]),
                    "enums": len(types["enums"]),
                    "interfaces": len(types["interfaces"]),
                    "scalars": len(types["scalars"]),
                    "unions": len(types["unions"]),
                },
            }

        if action == "generate_queries":
            if not schema_data:
                return {"error": "schema_data parameter required for this action"}

            queries = _generate_sample_queries(schema_data)

            return {
                "queries": queries,
                "total_queries": len([q for q in queries if q["category"] == "query"]),
                "total_mutations": len([q for q in queries if q["category"] == "mutation"]),
            }

        if action == "security_analysis":
            if not schema_data:
                return {"error": "schema_data parameter required for this action"}

            return _analyze_security(schema_data)

        return {"error": f"Unknown action: {action}"}

    except Exception as e:
        return {"error": f"GraphQL introspection failed: {e!s}"}
