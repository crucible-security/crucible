"""Response extraction utilities for parsing agent responses.

Uses JMESPath expressions to extract the actual agent response text
from nested JSON response bodies returned by various AI agent frameworks
(OpenAI, LangChain, Glean, Anthropic, etc.).
"""

from __future__ import annotations

import json
from typing import Any

import jmespath  # type: ignore[import-untyped]

from crucible.models import DEFAULT_RESPONSE_PATHS


def extract_response(raw_text: str, response_path: str = "") -> str:
    """Extract the agent's response text from a raw HTTP response body.

    Args:
        raw_text: The raw HTTP response body text.
        response_path: Optional JMESPath expression to extract the response.
            If empty, auto-detection is attempted using common paths.

    Returns:
        The extracted response text, or the original raw text if extraction fails.
    """
    # Try to parse as JSON first
    try:
        data: Any = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        return raw_text  # Not JSON, return raw text

    # If data is a plain string value, return it directly
    if isinstance(data, str):
        return data

    # If data is not a dict/list, JMESPath won't help
    if not isinstance(data, (dict | list)):
        return raw_text

    # If explicit path provided, use it
    if response_path:
        result = jmespath.search(response_path, data)
        if result is not None:
            return str(result)
        return raw_text  # Path didn't match, fall back to raw

    # Auto-detect: try common response paths in priority order
    for path in DEFAULT_RESPONSE_PATHS:
        try:
            result = jmespath.search(path, data)
            if result is not None:
                return str(result)
        except jmespath.exceptions.JMESPathError:
            continue

    return raw_text  # No match, return raw
