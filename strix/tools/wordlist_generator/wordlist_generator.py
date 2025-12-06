"""Wordlist generation tool for security testing."""

import itertools
import string
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "generate_from_target",
    "combine_lists",
    "apply_rules",
    "generate_permutations",
    "generate_common",
]


@register_tool(sandbox_execution=True)
def wordlist_generator(
    action: ToolAction,
    target_info: dict | None = None,
    words: list[str] | None = None,
    base_words: list[str] | None = None,
    rules: list[str] | None = None,
    charset: str | None = None,
    min_length: int | None = None,
    max_length: int | None = None,
    category: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Wordlist generation tool for security testing.

    Args:
        action: The action to perform
        target_info: Target information for custom wordlist generation
        words: Words for combination or rule application
        base_words: Base words for permutations
        rules: Transformation rules to apply
        charset: Character set for generation
        min_length: Minimum word length
        max_length: Maximum word length
        category: Category of common wordlist

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "target_info", "words", "base_words", "rules",
        "charset", "min_length", "max_length", "category",
    }
    VALID_ACTIONS = [
        "generate_from_target",
        "combine_lists",
        "apply_rules",
        "generate_permutations",
        "generate_common",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "wordlist_generator"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "wordlist_generator"):
        return action_error

    if action == "generate_from_target":
        target = target_info or {
            "company": "Acme",
            "domain": "acme.com",
            "industry": "technology",
        }

        company = target.get("company", "Company")
        domain = target.get("domain", "company.com")
        current_year = 2024

        # Generate target-specific words
        generated_words = []

        # Company name variations
        company_lower = company.lower()
        company_upper = company.upper()
        company_title = company.title()

        for name in [company_lower, company_upper, company_title]:
            generated_words.append(name)
            # With years
            for year in range(current_year - 5, current_year + 2):
                generated_words.append(f"{name}{year}")
                generated_words.append(f"{name}{year}!")
                generated_words.append(f"{name}@{year}")
                generated_words.append(f"{name}#{year}")

        # Common password patterns
        patterns = [
            f"{company_title}123",
            f"{company_title}123!",
            f"{company_title}!",
            f"{company_title}@123",
            f"Welcome{company_title}",
            f"Password{company_title}",
            f"{company_lower}admin",
            f"admin{company_lower}",
        ]
        generated_words.extend(patterns)

        # Seasonal patterns
        seasons = ["Winter", "Spring", "Summer", "Fall", "Autumn"]
        for season in seasons:
            for year in range(current_year - 1, current_year + 1):
                generated_words.append(f"{season}{year}")
                generated_words.append(f"{season}{year}!")
                generated_words.append(f"{season}@{year}")

        # Domain-based
        domain_parts = domain.replace('.', '').replace('-', '')
        generated_words.append(domain_parts)
        generated_words.append(f"{domain_parts}123")

        return {
            "action": "generate_from_target",
            "target_info": target,
            "wordlist": generated_words[:100],  # Limit output
            "total_generated": len(generated_words),
            "categories_used": [
                "Company name variations",
                "Year combinations",
                "Common password patterns",
                "Seasonal patterns",
                "Domain-based words",
            ],
            "recommendations": [
                "Add employee names if known",
                "Include product names",
                "Add office locations",
                "Consider regional variations",
            ],
            "save_command": f'''
# Save wordlist to file
cat << 'EOF' > {company_lower}_wordlist.txt
{chr(10).join(generated_words[:50])}
EOF
''',
        }

    elif action == "combine_lists":
        word_list = words or ["admin", "user", "test"]

        # Generate combinations
        combinations = []

        # Append numbers
        for word in word_list:
            combinations.append(word)
            for num in ["1", "12", "123", "1234", "01", "001"]:
                combinations.append(f"{word}{num}")
                combinations.append(f"{num}{word}")

        # Append special chars
        for word in word_list:
            for char in ["!", "@", "#", "$", "."]:
                combinations.append(f"{word}{char}")
                combinations.append(f"{char}{word}")

        # Word combinations
        for w1, w2 in itertools.combinations(word_list, 2):
            combinations.append(f"{w1}{w2}")
            combinations.append(f"{w2}{w1}")
            combinations.append(f"{w1}_{w2}")
            combinations.append(f"{w1}.{w2}")
            combinations.append(f"{w1}-{w2}")

        return {
            "action": "combine_lists",
            "input_words": word_list,
            "combined_wordlist": combinations[:200],
            "total_generated": len(combinations),
            "combination_types": [
                "Number suffixes/prefixes",
                "Special character appending",
                "Word concatenation",
                "Separator variations",
            ],
        }

    elif action == "apply_rules":
        word_list = words or ["password", "admin", "secret"]
        rule_list = rules or ["capitalize", "leet", "append_year", "reverse"]

        transformed = []

        for word in word_list:
            transformed.append(word)

            if "capitalize" in rule_list:
                transformed.append(word.capitalize())
                transformed.append(word.upper())
                transformed.append(word.lower())
                transformed.append(word.title())

            if "leet" in rule_list:
                leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                leet_word = ''.join(leet_map.get(c.lower(), c) for c in word)
                transformed.append(leet_word)
                transformed.append(leet_word.upper())

            if "append_year" in rule_list:
                for year in [2023, 2024, 2025]:
                    transformed.append(f"{word}{year}")
                    transformed.append(f"{word.capitalize()}{year}")
                    transformed.append(f"{word}{year}!")

            if "append_special" in rule_list:
                for char in ["!", "@", "#", "123", "!"]:
                    transformed.append(f"{word}{char}")

            if "reverse" in rule_list:
                transformed.append(word[::-1])

            if "double" in rule_list:
                transformed.append(word + word)

        # Remove duplicates while preserving order
        seen = set()
        unique_transformed = []
        for w in transformed:
            if w not in seen:
                seen.add(w)
                unique_transformed.append(w)

        return {
            "action": "apply_rules",
            "input_words": word_list,
            "rules_applied": rule_list,
            "transformed_wordlist": unique_transformed[:150],
            "total_generated": len(unique_transformed),
            "available_rules": [
                "capitalize - Case variations",
                "leet - L33t speak substitutions",
                "append_year - Add years",
                "append_special - Add special chars",
                "reverse - Reverse string",
                "double - Duplicate word",
            ],
            "hashcat_equivalent": '''
# Hashcat rules for similar transformations
hashcat -a 0 -m 1000 hashes.txt wordlist.txt -r rules/best64.rule
hashcat -a 0 -m 1000 hashes.txt wordlist.txt -r rules/d3ad0ne.rule
''',
        }

    elif action == "generate_permutations":
        base = base_words or ["admin"]
        min_len = min_length or 4
        max_len = max_length or 8
        chars = charset or "abc123"

        permutations = []

        # Generate based on base words with permutations
        for word in base:
            permutations.append(word)

            # Append characters
            for length in range(1, min(4, max_len - len(word) + 1)):
                for combo in itertools.product(chars, repeat=length):
                    suffix = ''.join(combo)
                    new_word = f"{word}{suffix}"
                    if min_len <= len(new_word) <= max_len:
                        permutations.append(new_word)
                        if len(permutations) > 1000:
                            break
                if len(permutations) > 1000:
                    break

        # Pure character permutations (limited)
        if len(permutations) < 500:
            for length in range(min_len, min(max_len + 1, 5)):
                for combo in itertools.product(chars, repeat=length):
                    permutations.append(''.join(combo))
                    if len(permutations) > 1000:
                        break
                if len(permutations) > 1000:
                    break

        return {
            "action": "generate_permutations",
            "base_words": base,
            "charset": chars,
            "length_range": f"{min_len}-{max_len}",
            "permutations": permutations[:200],
            "total_generated": len(permutations),
            "note": "Limited to 1000 for performance",
            "crunch_command": f'''
# Generate with crunch for larger lists
crunch {min_len} {max_len} {chars} -o wordlist.txt

# With pattern
crunch {min_len} {max_len} -t {base[0]}@@@ -o wordlist.txt
''',
        }

    elif action == "generate_common":
        cat = category or "passwords"

        wordlists = {
            "passwords": [
                "password", "123456", "password123", "admin", "letmein",
                "welcome", "monkey", "dragon", "master", "qwerty",
                "login", "passw0rd", "hello", "charlie", "donald",
                "password1", "qwerty123", "iloveyou", "sunshine", "princess",
                "admin123", "welcome1", "password!", "P@ssw0rd", "Password1",
            ],
            "usernames": [
                "admin", "administrator", "root", "user", "guest",
                "test", "demo", "operator", "manager", "support",
                "service", "backup", "www", "ftp", "mail",
                "webmaster", "postmaster", "sysadmin", "oracle", "mysql",
            ],
            "directories": [
                "admin", "administrator", "backup", "config", "dashboard",
                "login", "api", "v1", "v2", "internal", "dev", "test",
                "staging", "prod", "uploads", "files", "images", "docs",
                "private", "secret", "hidden", ".git", ".svn", ".env",
                "wp-admin", "phpmyadmin", "cpanel", "webmail", "portal",
            ],
            "subdomains": [
                "www", "mail", "ftp", "localhost", "webmail",
                "smtp", "pop", "ns1", "ns2", "cpanel", "whm",
                "admin", "api", "dev", "staging", "test", "beta",
                "m", "mobile", "app", "blog", "shop", "store",
                "secure", "vpn", "remote", "portal", "intranet",
            ],
            "api_endpoints": [
                "/api", "/api/v1", "/api/v2", "/graphql", "/rest",
                "/users", "/admin", "/login", "/auth", "/token",
                "/register", "/password", "/reset", "/profile", "/account",
                "/search", "/upload", "/download", "/export", "/import",
            ],
        }

        selected = wordlists.get(cat, wordlists["passwords"])

        return {
            "action": "generate_common",
            "category": cat,
            "wordlist": selected,
            "total_words": len(selected),
            "available_categories": list(wordlists.keys()),
            "seclists_paths": {
                "passwords": "/usr/share/seclists/Passwords/Common-Credentials/",
                "usernames": "/usr/share/seclists/Usernames/",
                "directories": "/usr/share/seclists/Discovery/Web-Content/",
                "subdomains": "/usr/share/seclists/Discovery/DNS/",
            },
            "recommended_lists": [
                "rockyou.txt - 14 million passwords",
                "SecLists - Comprehensive security wordlists",
                "CeWL - Custom wordlist generator from websites",
                "CUPP - Common User Password Profiler",
            ],
        }

    return generate_usage_hint("wordlist_generator", VALID_ACTIONS)
