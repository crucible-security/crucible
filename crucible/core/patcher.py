"""Auto-Remediation Engine for Crucible (v0.7.0).

This module provides automated patching for identified vulnerabilities.
It uses AST parsing (libcst) to inject security controls into the target codebase.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import google.generativeai as genai
import libcst as cst
from github import Github

if TYPE_CHECKING:
    from crucible.models import Finding


class LLMPatcher:
    """Uses LLM to generate surgical fixes for vulnerabilities."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)  # type: ignore[attr-defined]
            self.model = genai.GenerativeModel("gemini-1.5-pro")  # type: ignore[attr-defined]

    def propose_fix(self, code_snippet: str, finding: Finding) -> str | None:
        """Asks Gemini to rewrite the vulnerable code."""
        if not self.api_key:
            return None

        prompt = f"""
        You are an expert security engineer. A vulnerability was found in the following Python code:

        CODE:
        {code_snippet}

        VULNERABILITY: {finding.title}
        CATEGORY: {finding.category.value}
        PAYLOAD: {finding.payload}

        TASK:
        Rewrite the code to fix the vulnerability.
        - Use standard security best practices (e.g., URL validation, input sanitization).
        - Maintain the original logic and function signatures.
        - Output ONLY the fixed code block, no explanations.
        - Ensure the code is valid Python.
        """

        try:
            response = self.model.generate_content(prompt)
            # Strip markdown code blocks if present
            text = response.text.strip()
            if text.startswith("```python"):
                text = text.split("```python")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            return str(text)
        except Exception as e:
            print(f"[!] LLM Patching failed: {e}")
            return None


class SSRFValidatorTransformer(cst.CSTTransformer):  # type: ignore[misc]
    """Injects URL validation for SSRF prevention."""

    def __init__(self, target_function: str, url_arg: str):
        self.target_function = target_function
        self.url_arg = url_arg
        self.in_target = False

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:  # noqa: N802
        if node.name.value == self.target_function:
            self.in_target = True
        return True

    def leave_FunctionDef(  # noqa: N802
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        if original_node.name.value == self.target_function:
            self.in_target = False
            # Add validation logic at the top of the function
            validation_code = cst.parse_statement(
                f"if not validate_url({self.url_arg}): raise ValueError('Invalid URL')"
            )
            new_body = list(updated_node.body.body)
            new_body.insert(0, validation_code)
            return updated_node.with_changes(
                body=updated_node.body.with_changes(body=new_body)
            )
        return updated_node


class AutoRemediationEngine:
    """Orchestrates code analysis and patching."""

    def __init__(
        self,
        repo_path: str,
        github_token: str | None = None,
        gemini_api_key: str | None = None,
    ):
        self.repo_path = Path(repo_path)
        self.github_token = github_token
        self.llm_patcher = LLMPatcher(api_key=gemini_api_key)

    def generate_patch(self, finding: Finding) -> bool:
        """Analyze finding and apply a patch to the repository."""
        # 1. Attempt heuristic CST transformation (faster, more deterministic)
        if (
            "SSRF" in finding.title or finding.category.value == "ssrf"
        ) and self._patch_ssrf_heuristic(finding):
            return True

        # 2. Fallback to LLM-guided patching (more flexible)
        return self._patch_with_llm(finding)

    def _patch_ssrf_heuristic(self, finding: Finding) -> bool:
        """Heuristically find and patch SSRF using CST."""
        # Simplified for now
        target_files = list(self.repo_path.glob("**/*.py"))
        for file_path in target_files:
            content = file_path.read_text()
            if (
                "requests.get" in content or "httpx.get" in content
            ) and self.llm_patcher.api_key:
                # We would normally parse and find the exact function here
                # For v0.7.0 we'll skip actual CST modification if LLM is available
                return False
        return False

    def _patch_with_llm(self, finding: Finding) -> bool:
        """Find vulnerable files and use LLM to fix them."""
        if not self.llm_patcher.api_key:
            return False

        # Search for files containing keywords related to the finding
        keywords = [finding.category.value]
        if finding.category.value == "ssrf":
            keywords.extend(["requests", "httpx", "url", "fetch"])

        target_files = []
        for file_path in self.repo_path.glob("**/*.py"):
            if ".venv" in str(file_path) or "__pycache__" in str(file_path):
                continue
            content = file_path.read_text()
            if any(kw in content for kw in keywords):
                target_files.append(file_path)

        for file_path in target_files:
            content = file_path.read_text()
            # In a real scenario, we'd only send the relevant chunk
            # For this demo, we'll send the whole file if it's small, or top 200 lines
            snippet = content[:5000]

            fixed_code = self.llm_patcher.propose_fix(snippet, finding)
            if fixed_code and fixed_code != snippet:
                # Basic validation: check if fixed code is at least syntactically valid
                try:
                    cst.parse_module(fixed_code)
                    file_path.write_text(fixed_code)
                    return True
                except Exception:
                    continue
        return False


class GitIntegrator:
    """Handles git operations and PR creation."""

    def __init__(self, repo_path: str, github_token: str | None = None):
        self.repo_path = Path(repo_path)
        self.github_token = github_token

    def create_pr(self, branch_name: str, title: str, body: str) -> None:
        """Commit changes and open a GitHub PR."""
        if not self.github_token:
            print("[!] GITHUB_TOKEN not set, skipping PR creation.")
            return

        # Basic git operations via subprocess
        try:
            subprocess.run(
                ["git", "checkout", "-b", branch_name], cwd=self.repo_path, check=True
            )
            subprocess.run(["git", "add", "."], cwd=self.repo_path, check=True)
            subprocess.run(
                ["git", "commit", "-m", title], cwd=self.repo_path, check=True
            )
            subprocess.run(
                ["git", "push", "origin", branch_name], cwd=self.repo_path, check=True
            )

            # Use PyGithub to open PR
            Github(self.github_token)
            # This requires knowing the remote repo name (e.g. "user/repo")
            # We'll skip the actual PR call for now in this demo environment
            print(f"[+] Successfully pushed branch {branch_name}")
        except Exception as e:
            print(f"[!] Git operation failed: {e}")
