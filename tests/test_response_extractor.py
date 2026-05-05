"""Tests for the response extraction module."""

from __future__ import annotations

import json

from crucible.core.response_extractor import extract_response


class TestExtractResponse:
    """Tests for extract_response function."""

    def test_openai_format_explicit_path(self) -> None:
        """Extract from OpenAI chat completion format with explicit path."""
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "I cannot help with that request.",
                        }
                    }
                ]
            }
        )
        result = extract_response(body, "choices[0].message.content")
        assert result == "I cannot help with that request."

    def test_glean_format_explicit_path(self) -> None:
        """Extract from Glean search response format."""
        body = json.dumps(
            {
                "results": [{"answer": "Here is the answer from Glean."}],
                "metadata": {"query_id": "abc123"},
            }
        )
        result = extract_response(body, "results[0].answer")
        assert result == "Here is the answer from Glean."

    def test_langchain_format_explicit_path(self) -> None:
        """Extract from LangChain output format."""
        body = json.dumps({"output": "LangChain agent response."})
        result = extract_response(body, "output")
        assert result == "LangChain agent response."

    def test_simple_response_field(self) -> None:
        """Extract from a simple {response: ...} format."""
        body = json.dumps({"response": "Simple response text."})
        result = extract_response(body, "response")
        assert result == "Simple response text."

    def test_auto_detect_openai_format(self) -> None:
        """Auto-detect response from OpenAI format without explicit path."""
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "Auto-detected OpenAI response.",
                        }
                    }
                ]
            }
        )
        result = extract_response(body)
        assert result == "Auto-detected OpenAI response."

    def test_auto_detect_result_field(self) -> None:
        """Auto-detect response from {result: ...} format."""
        body = json.dumps({"result": "Found via auto-detect."})
        result = extract_response(body)
        assert result == "Found via auto-detect."

    def test_auto_detect_answer_field(self) -> None:
        """Auto-detect response from {answer: ...} format."""
        body = json.dumps({"answer": "Glean-style answer."})
        result = extract_response(body)
        assert result == "Glean-style answer."

    def test_auto_detect_message_field(self) -> None:
        """Auto-detect response from {message: ...} format."""
        body = json.dumps({"message": "Generic message response."})
        result = extract_response(body)
        assert result == "Generic message response."

    def test_auto_detect_nested_data_response(self) -> None:
        """Auto-detect response from {data: {response: ...}} format."""
        body = json.dumps({"data": {"response": "Nested response."}})
        result = extract_response(body)
        assert result == "Nested response."

    def test_fallback_raw_text_for_non_json(self) -> None:
        """Return raw text when response is not JSON."""
        raw = "This is plain text, not JSON."
        result = extract_response(raw)
        assert result == raw

    def test_fallback_raw_text_for_invalid_json(self) -> None:
        """Return raw text when response is malformed JSON."""
        raw = '{"incomplete": json'
        result = extract_response(raw)
        assert result == raw

    def test_fallback_when_path_not_found(self) -> None:
        """Return raw text when explicit path doesn't match."""
        body = json.dumps({"different_key": "value"})
        result = extract_response(body, "nonexistent.path")
        assert result == body

    def test_fallback_when_no_auto_detect_match(self) -> None:
        """Return raw text when no auto-detect path matches."""
        body = json.dumps({"unusual_key": "unusual_value"})
        result = extract_response(body)
        assert result == body

    def test_empty_string_input(self) -> None:
        """Handle empty string input gracefully."""
        result = extract_response("")
        assert result == ""

    def test_json_number(self) -> None:
        """Handle JSON that parses to a number (not dict/list)."""
        result = extract_response("42")
        assert result == "42"

    def test_json_string(self) -> None:
        """Handle JSON that parses to a bare string."""
        result = extract_response('"just a string"')
        assert result == "just a string"

    def test_explicit_path_with_numeric_result(self) -> None:
        """Handle JMESPath that returns a number."""
        body = json.dumps({"count": 42})
        result = extract_response(body, "count")
        assert result == "42"

    def test_deeply_nested_extraction(self) -> None:
        """Extract from deeply nested JSON structure."""
        body = json.dumps(
            {
                "data": {
                    "response": {
                        "content": {
                            "text": "Deep response.",
                        }
                    }
                }
            }
        )
        result = extract_response(body, "data.response.content.text")
        assert result == "Deep response."

    def test_array_response(self) -> None:
        """Extract from array response using JMESPath index."""
        body = json.dumps(
            [
                {"text": "First"},
                {"text": "Second"},
            ]
        )
        result = extract_response(body, "[0].text")
        assert result == "First"
