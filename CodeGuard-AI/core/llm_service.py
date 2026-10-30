"""
CodeGuard AI 2.0 - LLM Service (Google Gemini)
Communicates with Google Gemini using robust JSON-schema prompting, timeout protection,
exponential backoff retry mechanisms, connection testing, and structured Pydantic deserialization.
"""
from __future__ import annotations
import json
import time
import re
import os
import urllib.request
import urllib.error
from typing import Optional, List, Dict, Any, Tuple
from core.schemas import ReviewResult, CodeIssue
from config.settings import GEMINI_API_KEY, GEMINI_MODEL, LLM_TIMEOUT
from core.connection_tester import verify_gemini_connection, run_gemini_diagnostics


SYSTEM_PROMPT = """You are an elite Software Security Architect and Principal Code Quality Auditor.
Analyze the provided {language} source code. Your goal is to identify genuine defects, logical bugs, security vulnerabilities, edge-case failures, and architectural issues.

You MUST respond strictly with a valid, raw JSON object (NO markdown backticks, NO prose preamble, NO trailing text).
The JSON MUST follow this exact schema:

{{
  "summary": "Concise 2-3 sentence executive assessment of the codebase.",
  "overall_quality": "Good",   // Must be one of: "Good", "Fair", "Poor"
  "issues": [
    {{
      "issue_type": "descriptive_snake_case_type",
      "category": "Security Vulnerabilities",  // Must be one of: "Syntax Errors", "Runtime Errors", "Logical Errors", "Security Vulnerabilities", "Performance Issues", "Code Quality Issues", "Exception Handling", "Resource Management"
      "title": "Clear, concise title of the flaw",
      "description": "Thorough explanation of the root cause and why it is a defect.",
      "severity": "High",     // Must be one of: "Critical", "High", "Medium", "Low", "Informational"
      "line_number": 12,       // Integer line number or null if general
      "end_line_number": 14,   // Integer ending line number or null
      "evidence": "exact problematic code line from source",
      "suggested_fix": "Actionable explanation of how to fix this issue",
      "corrected_code": "The exact corrected code snippet",
      "impact": "Operational or security outcome if unpatched",
      "confidence": 0.85,      // Float between 0.0 and 1.0 representing estimated certainty
      "confidence_explanation": "Contextual reason for this confidence assessment"
    }}
  ],
  "recommendations": [
    "Specific best-practice recommendation 1",
    "Specific best-practice recommendation 2"
  ]
}}

CRITICAL INSTRUCTIONS:
1. Grounding: Do NOT invent phantom bugs. If the code is well-written and bug-free, return an empty issues list and an overall_quality of "Good".
2. Accuracy: Ensure line_number and evidence match the provided code lines exactly.
3. Realistic Confidence: Assign a genuine confidence rating (0.0 to 1.0). If uncertain, state your reasoning.
4. Output: ONLY the JSON object.
"""


class LLMService:
    """Production-grade client wrapper for Google Gemini API."""

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None) -> None:
        self._api_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", GEMINI_API_KEY)
        self._model_name = model_name or os.getenv("GEMINI_MODEL", GEMINI_MODEL)
        self._available = False
        self._error_message: Optional[str] = None
        self._last_diagnostics: Optional[Dict[str, Any]] = None
        self._init_client()

    def _init_client(self) -> None:
        if self._api_key is None:
            self._api_key = os.getenv("GEMINI_API_KEY", "")
        if not self._model_name:
            self._model_name = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

        if not self._api_key or self._api_key == "your_gemini_api_key_here":
            self._available = False
            self._error_message = "GEMINI_API_KEY is not configured in environment or .env file."
            return

        self._available = True
        self._error_message = None

    def configure_key(self, api_key: str, model_name: Optional[str] = None) -> Tuple[bool, str]:
        """Dynamically configure and validate a new API key."""
        clean_key = (api_key or "").strip()
        if not clean_key:
            self._api_key = ""
            self._available = False
            self._error_message = "Provided API key is empty."
            return False, self._error_message

        if model_name:
            self._model_name = model_name.strip()

        # Run full network diagnostics pipeline
        diag = run_gemini_diagnostics(clean_key, self._model_name, connect_timeout=15, request_timeout=60)
        self._last_diagnostics = diag

        if diag["overall_status"] == "Connected":
            self._api_key = clean_key
            self._available = True
            self._error_message = None
            os.environ["GEMINI_API_KEY"] = clean_key
            os.environ["GEMINI_MODEL"] = self._model_name
            return True, f"Connection verified successfully with {self._model_name}."
        else:
            self._available = False
            category = diag.get("error_category") or "Connection Error"
            fail_msg = "Unknown error"
            for step in ["auth", "model", "https", "tcp", "dns"]:
                s_info = diag.get(step, {})
                if s_info.get("status") == "failed":
                    fail_msg = s_info.get("message")
                    break
            self._error_message = f"{category}: {fail_msg}"
            return False, self._error_message

    def run_diagnostics(self) -> Dict[str, Any]:
        """Run diagnostics on current configuration."""
        diag = run_gemini_diagnostics(self._api_key, self._model_name, connect_timeout=15, request_timeout=60)
        self._last_diagnostics = diag
        return diag

    def clear_key(self) -> None:
        """Clear active key from in-memory service."""
        self._api_key = ""
        self._available = False
        self._error_message = "API Key cleared by user."
        self._last_diagnostics = None
        if "GEMINI_API_KEY" in os.environ:
            del os.environ["GEMINI_API_KEY"]

    def test_connection(self) -> Tuple[bool, str]:
        """Test the live API connection."""
        if not self._api_key:
            return False, "GEMINI_API_KEY is not configured."
        return verify_gemini_connection(self._api_key, self._model_name, timeout=60)

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def status_message(self) -> str:
        if self._available:
            return f"Gemini ({self._model_name}) Connected & Ready."
        return self._error_message or "LLM service inactive."

    def _call_gemini_rest(self, prompt: str, timeout: int = 60) -> str:
        """Execute REST call to Gemini generateContent endpoint."""
        clean_model = self._model_name.replace("models/", "").strip()
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent?key={self._api_key}"

        payload = json.dumps({
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.15,
                "maxOutputTokens": 4096,
            }
        }).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_body = response.read().decode("utf-8")
            data = json.loads(res_body)
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
            return ""

    def analyse(self, code: str, language: str) -> ReviewResult:
        """
        Analyze code with retry backoff and structured parsing.
        Degrades gracefully without raising exceptions.
        """
        if not self._available:
            return ReviewResult(
                summary="LLM analysis unavailable (API key missing or client initialization failed).",
                language=language,
                overall_quality="Fair",
                analysis_mode="rule_based",
                error=self._error_message,
                analyzer_statuses={"llm_service": "Unavailable"}
            )

        prompt = SYSTEM_PROMPT.format(language=language) + f"\n\nSOURCE CODE TO AUDIT:\n```{language.lower()}\n{code}\n```"

        raw_response = None
        last_exception = None

        # Exponential backoff retry loop (up to 3 attempts) for transient errors (500, 503, 429)
        for attempt in range(1, 4):
            try:
                raw_response = self._call_gemini_rest(prompt, timeout=60)
                if raw_response:
                    break
            except urllib.error.HTTPError as e:
                last_exception = e
                # Terminal errors: fail fast without retrying
                if e.code in (400, 401, 403, 404):
                    break
                time.sleep(attempt * 1.5)
            except Exception as e:
                last_exception = e
                time.sleep(attempt * 1.0)

        if not raw_response:
            return ReviewResult(
                summary="LLM request failed after retries.",
                language=language,
                overall_quality="Fair",
                analysis_mode="rule_based",
                error=f"Gemini API request failed: {last_exception}",
                analyzer_statuses={"llm_service": f"Failed: {last_exception}"}
            )

        # Clean markdown code blocks if the LLM wrapped response
        clean_text = raw_response.strip()
        if clean_text.startswith("```"):
            clean_text = re.sub(r"^```[a-zA-Z]*\n", "", clean_text)
            clean_text = re.sub(r"\n```$", "", clean_text).strip()

        try:
            data = json.loads(clean_text)
        except json.JSONDecodeError as err:
            return ReviewResult(
                summary="LLM returned non-JSON response.",
                language=language,
                overall_quality="Fair",
                analysis_mode="rule_based",
                error=f"JSON decoding error: {err}",
                analyzer_statuses={"llm_service": "JSON Error"}
            )

        parsed_issues: List[CodeIssue] = []
        for item in data.get("issues", []):
            try:
                line_no = item.get("line_number")
                if line_no is not None:
                    try:
                        line_no = int(line_no)
                    except (ValueError, TypeError):
                        line_no = None

                end_line_no = item.get("end_line_number")
                if end_line_no is not None:
                    try:
                        end_line_no = int(end_line_no)
                    except (ValueError, TypeError):
                        end_line_no = line_no

                conf = item.get("confidence", 0.85)
                try:
                    conf = float(conf)
                except (ValueError, TypeError):
                    conf = 0.85

                conf_expl = item.get("confidence_explanation") or "Contextual probabilistic assessment by Gemini LLM."

                issue = CodeIssue(
                    issue_type=str(item.get("issue_type", "code_defect")),
                    category=str(item.get("category", "Logical Errors")),
                    title=str(item.get("title", "Detected Issue")),
                    description=str(item.get("description", "")),
                    severity=str(item.get("severity", "Medium")),
                    line_number=line_no,
                    end_line_number=end_line_no,
                    evidence=item.get("evidence"),
                    suggested_fix=item.get("suggested_fix"),
                    corrected_code=item.get("corrected_code"),
                    impact=item.get("impact"),
                    confidence=conf,
                    confidence_explanation=conf_expl,
                    detection_sources=["llm_gemini"],
                    source="llm_gemini",
                )
                parsed_issues.append(issue)
            except Exception:
                continue

        summary = data.get("summary", "LLM analysis complete.")
        quality = data.get("overall_quality", "Fair")
        recommendations = data.get("recommendations", [])

        return ReviewResult(
            summary=summary,
            language=language,
            overall_quality=quality,
            issues=parsed_issues,
            recommendations=recommendations,
            analysis_mode="llm",
            analyzer_statuses={"llm_service": "Success"},
        )
