"""Small, explainable teaching rules. Not a complete attack detector."""

import html
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus, urlsplit


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: str
    description: str


RULES = (
    Rule("SQLI-001", "SQL Injection",
         r"\bunion\s+(?:all\s+)?select\b|['\"]\s*(?:or|and)\s+(?:1\s*=\s*1|'([^']{1,32})'\s*=\s*'\1')",
         "UNION SELECT or a typical always-true condition after a quote"),
    Rule("XSS-001", "Cross-site scripting",
         r"<\s*script\b|\bon(?:error|load|click|focus)\s*=|javascript\s*:",
         "Script tags, selected event attributes, or javascript: URLs"),
    Rule("PATH-001", "Path traversal",
         r"(?:^|[/\\])\.\.(?:[/\\]|$)",
         "Attempts to reach a parent directory using ../ or ..\\"),
    Rule("CMD-001", "Command injection",
         r"(?:;|\|\||&&|\||\n)\s*(?:id|whoami|cat|ls|curl|wget|sh|bash|powershell|cmd)(?:\s|$)|\$\([^)]{1,200}\)|`[^`]{1,200}`",
         "Shell separators followed by common commands, or command substitution"),
)
COMPILED = [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in RULES]


class InvalidPayload(ValueError):
    pass


def normalize(value):
    """Normalize a copy for inspection; the original request is forwarded intact."""
    for _ in range(3):
        decoded = html.unescape(unquote_plus(value))
        if decoded == value:
            break
        value = decoded
    # Match both UNION/**/SELECT and UN/**/ION through two variants below.
    return value


def json_strings(value, depth=0):
    if depth > 32:
        raise InvalidPayload("JSON nesting exceeds 32 levels")
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from json_strings(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from json_strings(child, depth + 1)
    elif isinstance(value, str):
        yield value


def inspect_request(target, headers, body):
    """Return first matching rule and source, without retaining payload contents."""
    parts = urlsplit(target)
    fields = [("path", parts.path)]
    for key, value in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=256):
        fields.extend((("query", key), ("query", value)))
    for name in ("User-Agent", "Referer", "Cookie"):
        for value in headers.get_all(name, []):
            fields.append(("header", value))

    if body:
        content_type = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        try:
            decoded = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidPayload("Only UTF-8 request bodies are supported") from exc
        if content_type == "application/json":
            try:
                values = list(json_strings(json.loads(decoded)))
            except (ValueError, RecursionError) as exc:
                raise InvalidPayload("Invalid JSON or excessive nesting") from exc
            fields.extend(("json", value) for value in values)
        elif content_type == "application/x-www-form-urlencoded":
            for key, value in parse_qsl(decoded, keep_blank_values=True, max_num_fields=256):
                fields.extend((("form", key), ("form", value)))
        else:
            fields.append(("body", decoded))

    for source, value in fields:
        normalized = normalize(value)
        variants = (normalized, re.sub(r"/\*.*?\*/", " ", normalized, flags=re.S),
                    re.sub(r"/\*.*?\*/", "", normalized, flags=re.S))
        for rule, pattern in COMPILED:
            if any(pattern.search(variant) for variant in variants):
                return {"id": rule.id, "name": rule.name, "source": source}
    return None
