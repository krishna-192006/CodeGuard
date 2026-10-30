"""
CodeGuard AI 2.0 - Gemini Connection & Client Unit Tests
Validates key configuration, connection testing error mappings,
session state fallback, retry loops, and error isolation without requiring external network access.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import json
import urllib.error
from unittest.mock import patch, MagicMock
from core.llm_service import LLMService
from core.connection_tester import verify_gemini_connection
from core.schemas import ReviewResult


# 1. Missing API Key Validation
def test_missing_api_key_connection():
    success, msg = verify_gemini_connection("", "gemini-3.8-flash")
    assert not success
    assert "missing" in msg.lower() or "empty" in msg.lower()


# 2. Authentication Error (HTTP 400 / 403 API_KEY_INVALID)
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_auth_error_mapping(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_dns):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    err_body = json.dumps({"error": {"code": 400, "message": "API key not valid. Please pass a valid API key."}}).encode("utf-8")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=MagicMock(read=lambda: err_body)
    )
    success, msg = verify_gemini_connection("invalid_key_12345", "gemini-3.8-flash")
    assert not success
    assert "Authentication Failed" in msg or "Invalid" in msg


# 3. Model Not Found Error (HTTP 404)
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_model_not_found_mapping(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_dns):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    err_body = json.dumps({"error": {"code": 404, "message": "models/non-existent-model is not found"}}).encode("utf-8")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=MagicMock(read=lambda: err_body)
    )
    success, msg = verify_gemini_connection("valid_key", "non-existent-model")
    assert not success
    assert "Model Not Found" in msg or "404" in msg


# 4. Quota / Rate Limiting (HTTP 429)
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_rate_limit_mapping(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_dns):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    err_body = json.dumps({"error": {"code": 429, "message": "ResourceExhausted"}}).encode("utf-8")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=MagicMock(read=lambda: err_body)
    )
    success, msg = verify_gemini_connection("valid_key", "gemini-3.8-flash")
    assert not success
    assert "Rate Limit" in msg or "429" in msg or "Quota" in msg


# 5. Network Timeout Error
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_network_timeout_mapping(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_dns):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    mock_urlopen.side_effect = TimeoutError("Connection timed out")
    success, msg = verify_gemini_connection("valid_key", "gemini-3.8-flash", timeout=2)
    assert not success
    assert "Timeout" in msg or "timed out" in msg.lower()


# 6. Server Side Error (HTTP 500 / 503)
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_server_error_mapping(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_dns):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    err_body = json.dumps({"error": {"code": 503, "message": "The service is currently unavailable."}}).encode("utf-8")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=503,
        msg="Service Unavailable",
        hdrs={},
        fp=MagicMock(read=lambda: err_body)
    )
    success, msg = verify_gemini_connection("valid_key", "gemini-3.8-flash")
    assert not success
    assert "Google Service Error" in msg or "503" in msg or "Server Error" in msg


# 7. Successful Connection Mock
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_successful_connection(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_dns):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    success_body = json.dumps({"candidates": [{"content": {"parts": [{"text": "OK"}]}}]}).encode("utf-8")
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = MagicMock(read=lambda: success_body)
    mock_urlopen.return_value = mock_cm

    success, msg = verify_gemini_connection("valid_key", "gemini-3.8-flash")
    assert success
    assert "verified" in msg.lower()


# 8. Dynamic Key Configuration in LLMService
@patch("core.llm_service.run_gemini_diagnostics")
def test_llm_service_configure_key(mock_diag):
    mock_diag.return_value = {
        "dns": {"status": "passed", "message": "OK"},
        "tcp": {"status": "passed", "message": "OK"},
        "https": {"status": "passed", "message": "OK"},
        "auth": {"status": "passed", "message": "OK"},
        "model": {"status": "passed", "message": "OK"},
        "overall_status": "Connected"
    }
    service = LLMService(api_key="")
    assert not service.is_available

    ok, msg = service.configure_key("new_test_key_abc", "gemini-3.8-flash")
    assert ok
    assert service.is_available
    assert service.model_name == "gemini-3.8-flash"
    assert "Connected" in service.status_message


# 9. Clear Key Functionality
def test_llm_service_clear_key():
    service = LLMService(api_key="temporary_key_xyz")
    service.clear_key()
    assert not service.is_available
    assert "cleared" in service.status_message.lower()


# 10. Graceful Degradation on Inactive Service
def test_analyse_degrades_gracefully():
    service = LLMService(api_key="")
    result = service.analyse("def add(a, b): return a + b", "Python")
    assert isinstance(result, ReviewResult)
    assert result.analysis_mode == "rule_based"
    assert len(result.issues) == 0
    assert result.analyzer_statuses.get("llm_service") == "Unavailable"


# 11. Diagnostics - DNS Failure
@patch("socket.gethostbyname")
def test_diagnostics_dns_failure(mock_gethostbyname):
    import socket
    mock_gethostbyname.side_effect = socket.gaierror(11001, "getaddrinfo failed")
    from core.connection_tester import run_gemini_diagnostics

    diag = run_gemini_diagnostics(api_key="test_key", model_name="gemini-3.8-flash")
    assert diag["dns"]["status"] == "failed"
    assert "DNS" in diag["dns"]["message"]
    assert diag["overall_status"] == "Failed"


# 12. Diagnostics - TCP Timeout
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
def test_diagnostics_tcp_timeout(mock_create_conn, mock_gethostbyname):
    import socket
    mock_create_conn.side_effect = socket.timeout("timed out")
    from core.connection_tester import run_gemini_diagnostics

    diag = run_gemini_diagnostics(api_key="test_key", model_name="gemini-3.8-flash")
    assert diag["dns"]["status"] == "passed"
    assert diag["tcp"]["status"] == "failed"
    assert "Port 443" in diag["troubleshooting"] or "timed out" in diag["tcp"]["message"].lower()
    assert diag["overall_status"] == "Failed"


# 13. Diagnostics - HTTPS / SSL Failure
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_diagnostics_ssl_failure(mock_ssl_ctx, mock_create_conn, mock_gethostbyname):
    import ssl
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_context.wrap_socket.side_effect = ssl.SSLError("CERTIFICATE_VERIFY_FAILED")
    mock_ssl_ctx.return_value = mock_context
    from core.connection_tester import run_gemini_diagnostics

    diag = run_gemini_diagnostics(api_key="test_key", model_name="gemini-3.8-flash")
    assert diag["tcp"]["status"] == "passed"
    assert diag["https"]["status"] == "failed"
    assert "TLS/SSL" in diag["https"]["message"]
    assert diag["overall_status"] == "Failed"


# 14. Diagnostics - Auth / Key Failure (HTTP 400 API_KEY_INVALID)
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_diagnostics_auth_failure(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_gethostbyname):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    err_body = json.dumps({"error": {"message": "API key not valid. Please pass a valid API key.", "status": "INVALID_ARGUMENT"}}).encode("utf-8")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=MagicMock(read=lambda: err_body)
    )
    from core.connection_tester import run_gemini_diagnostics

    diag = run_gemini_diagnostics(api_key="bad_key", model_name="gemini-3.8-flash")
    assert diag["dns"]["status"] == "passed"
    assert diag["tcp"]["status"] == "passed"
    assert diag["https"]["status"] == "passed"
    assert diag["auth"]["status"] == "failed"
    assert "Invalid" in diag["auth"]["message"] or "Authentication Failed" in diag["auth"]["message"]
    assert diag["overall_status"] == "Failed"


# 15. Diagnostics - Model 404 Not Found
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_diagnostics_model_not_found(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_gethostbyname):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    err_body = json.dumps({"error": {"message": "models/non-existent-model is not found for API version v1beta", "status": "NOT_FOUND"}}).encode("utf-8")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=MagicMock(read=lambda: err_body)
    )
    from core.connection_tester import run_gemini_diagnostics

    diag = run_gemini_diagnostics(api_key="valid_key", model_name="non-existent-model")
    assert diag["auth"]["status"] == "passed"
    assert diag["model"]["status"] == "failed"
    assert "Model Not Found" in diag["model"]["message"]
    assert diag["overall_status"] == "Failed"


# 16. Diagnostics - Full Success
@patch("socket.gethostbyname", return_value="172.217.112.4")
@patch("socket.create_connection")
@patch("ssl.create_default_context")
@patch("urllib.request.urlopen")
def test_diagnostics_full_success(mock_urlopen, mock_ssl_ctx, mock_create_conn, mock_gethostbyname):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    mock_context = MagicMock()
    mock_wrapped_sock = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_sock
    mock_ssl_ctx.return_value = mock_context

    success_body = json.dumps({"candidates": [{"content": {"parts": [{"text": "Hello"}]}}]}).encode("utf-8")
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = MagicMock(read=lambda: success_body)
    mock_urlopen.return_value = mock_cm

    from core.connection_tester import run_gemini_diagnostics

    diag = run_gemini_diagnostics(api_key="valid_key", model_name="gemini-3.8-flash")
    assert diag["dns"]["status"] == "passed"
    assert diag["tcp"]["status"] == "passed"
    assert diag["https"]["status"] == "passed"
    assert diag["auth"]["status"] == "passed"
    assert diag["model"]["status"] == "passed"
    assert diag["overall_status"] == "Connected"

