"""
CodeGuard AI 2.0 - Gemini Network & Diagnostic Utility
Provides granular network diagnostics:
1. DNS Resolution
2. TCP Port 443 Connectivity
3. HTTPS Handshake & TLS
4. API Key Authentication
5. Model Availability for 'gemini-3.8-flash' (or configured model)
"""
from __future__ import annotations
import socket
import ssl
import urllib.request
import urllib.error
import json
import time
from typing import Dict, Any, Tuple, Optional

GEMINI_HOST = "generativelanguage.googleapis.com"
GEMINI_PORT = 443


def run_gemini_diagnostics(
    api_key: Optional[str] = None,
    model_name: str = "gemini-3.8-flash",
    connect_timeout: int = 15,
    request_timeout: int = 60,
) -> Dict[str, Any]:
    """
    Executes a structured diagnostic pipeline returning individual check results:
    - DNS Resolution
    - TCP Port 443 Connectivity
    - HTTPS / SSL Handshake
    - API Authentication
    - Model Availability
    """
    results: Dict[str, Any] = {
        "dns": {"status": "pending", "message": "Pending check", "ip": None},
        "tcp": {"status": "pending", "message": "Pending check"},
        "https": {"status": "pending", "message": "Pending check"},
        "auth": {"status": "pending", "message": "Pending check"},
        "model": {"status": "pending", "message": "Pending check", "model": model_name},
        "overall_status": "Failed",
        "error_category": None,
        "troubleshooting": None,
    }

    # 0. Quick pre-check for missing/empty key
    clean_key = (api_key or "").strip()
    if not clean_key or clean_key == "your_gemini_api_key_here":
        results["auth"] = {
            "status": "failed",
            "message": "GEMINI_API_KEY is not configured or is empty.",
        }
        results["model"] = {
            "status": "pending",
            "message": "Skipped (Awaiting API key authentication).",
            "model": model_name,
        }
        results["error_category"] = "Missing API Key"
        results["troubleshooting"] = "Please supply a valid Google Gemini API key to test authentication and model availability."
        # If API key is empty, don't attempt external network requests
        return results

    # 1. DNS Resolution Check
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(GEMINI_HOST)
        results["dns"] = {
            "status": "passed",
            "message": f"Successfully resolved {GEMINI_HOST} -> {resolved_ip}",
            "ip": resolved_ip,
        }
    except socket.gaierror as e:
        results["dns"] = {
            "status": "failed",
            "message": f"DNS Resolution Failed: [Errno {e.errno}] {e.strerror}. Unable to translate '{GEMINI_HOST}' to an IP address.",
            "ip": None,
        }
        results["error_category"] = "DNS Failure"
        results["troubleshooting"] = (
            "The system cannot resolve Google's API host. Check your computer's internet connection, "
            "DNS configuration, or company VPN/proxy settings."
        )
        return results
    except Exception as e:
        results["dns"] = {"status": "failed", "message": f"DNS Error: {e}", "ip": None}
        results["error_category"] = "DNS Error"
        return results

    # 2. TCP Port 443 Connectivity Check
    sock = None
    try:
        sock = socket.create_connection((GEMINI_HOST, GEMINI_PORT), timeout=connect_timeout)
        results["tcp"] = {
            "status": "passed",
            "message": f"TCP connection established to {resolved_ip}:{GEMINI_PORT}.",
        }
    except socket.timeout:
        results["tcp"] = {
            "status": "failed",
            "message": f"TCP Connection Timed Out after {connect_timeout}s.",
        }
        results["error_category"] = "Connection Timeout"
        results["troubleshooting"] = (
            f"Port {GEMINI_PORT} on {GEMINI_HOST} is unreachable within {connect_timeout}s. "
            "Outbound traffic on port 443 may be blocked by a local firewall or network sandbox."
        )
        return results
    except Exception as e:
        results["tcp"] = {
            "status": "failed",
            "message": f"TCP Connection Failed: {e}",
        }
        results["error_category"] = "TCP Failure"
        results["troubleshooting"] = f"Network socket connection failed: {e}"
        return results
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    # 3. HTTPS / TLS Handshake Check
    context = ssl.create_default_context()
    tls_sock = None
    try:
        raw_sock = socket.create_connection((GEMINI_HOST, GEMINI_PORT), timeout=connect_timeout)
        tls_sock = context.wrap_socket(raw_sock, server_hostname=GEMINI_HOST)
        cipher = tls_sock.cipher()
        results["https"] = {
            "status": "passed",
            "message": f"TLS Handshake succeeded ({cipher[0]}, {cipher[1]}).",
        }
    except ssl.SSLError as e:
        results["https"] = {
            "status": "failed",
            "message": f"TLS/SSL Certificate Verification Failed: {e}",
        }
        results["error_category"] = "TLS/SSL Failure"
        results["troubleshooting"] = "SSL handshake failed. Check system date/time or corporate SSL inspection certificates."
        return results
    except socket.timeout:
        results["https"] = {
            "status": "failed",
            "message": f"HTTPS Handshake timed out after {connect_timeout}s.",
        }
        results["error_category"] = "Connection Timeout"
        return results
    except Exception as e:
        results["https"] = {
            "status": "failed",
            "message": f"HTTPS Connection Failed: {e}",
        }
        results["error_category"] = "HTTPS Failure"
        return results
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except Exception:
                pass

    # If no API key provided, stop here with guidance
    clean_key = (api_key or "").strip()
    if not clean_key or clean_key == "your_gemini_api_key_here":
        results["auth"] = {
            "status": "failed",
            "message": "GEMINI_API_KEY is not configured.",
        }
        results["model"] = {
            "status": "pending",
            "message": "Skipped (Awaiting API key authentication).",
            "model": model_name,
        }
        results["error_category"] = "Missing API Key"
        results["troubleshooting"] = "Please supply a valid Google Gemini API key to test authentication and model availability."
        return results

    # 4. API Authentication & Model Availability Check
    # We probe with countTokens first: countTokens authenticates the key and verifies model
    # existence with minimal payload and immediate (<1s) latency, preventing inference queue timeouts.
    clean_model = model_name.replace("models/", "").strip()
    auth_endpoint = f"https://{GEMINI_HOST}/v1beta/models/{clean_model}:countTokens?key={clean_key}"
    auth_payload = json.dumps({"contents": [{"parts": [{"text": "Ping"}]}]}).encode("utf-8")

    req = urllib.request.Request(
        auth_endpoint,
        data=auth_payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=connect_timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results["auth"] = {
                "status": "passed",
                "message": "API key successfully authenticated with Google.",
            }
            results["model"] = {
                "status": "passed",
                "message": f"Model '{clean_model}' is available and responding.",
                "model": clean_model,
            }
            results["overall_status"] = "Connected"
            return results

    except urllib.error.HTTPError as e:
        status_code = e.code
        err_msg = ""
        try:
            err_json = json.loads(e.read().decode("utf-8"))
            err_msg = err_json.get("error", {}).get("message", "")
        except Exception:
            err_msg = str(e)

        if status_code in (400, 403):
            if "API key not valid" in err_msg or "INVALID_ARGUMENT" in err_msg or "PERMISSION_DENIED" in err_msg:
                results["auth"] = {
                    "status": "failed",
                    "message": f"Authentication Failed (HTTP {status_code}): Invalid or unauthorized Gemini API key.",
                }
                results["error_category"] = "Authentication Failure"
                results["troubleshooting"] = "Verify your API key in Google AI Studio (https://aistudio.google.com/app/apikey)."
            else:
                results["auth"] = {"status": "failed", "message": f"API Error (HTTP {status_code}): {err_msg}"}
                results["error_category"] = "API Error"
            return results

        elif status_code == 404:
            results["auth"] = {"status": "passed", "message": "API key is authenticated."}
            results["model"] = {
                "status": "failed",
                "message": f"Model Not Found (HTTP 404): '{clean_model}' is not recognized or not available to your key.",
                "model": clean_model,
            }
            results["error_category"] = "Model Not Found"
            results["troubleshooting"] = f"Model '{clean_model}' was not found. Please verify the exact model identifier."
            return results

        elif status_code == 429:
            results["auth"] = {"status": "passed", "message": "API key authenticated."}
            results["model"] = {
                "status": "failed",
                "message": "Rate Limit / Quota Exceeded (HTTP 429): Quota exhausted for this model.",
                "model": clean_model,
            }
            results["error_category"] = "Quota Exceeded"
            results["troubleshooting"] = "You have reached your request rate limit. Wait a few moments or verify billing limits."
            return results

        elif status_code in (500, 502, 503, 504):
            results["auth"] = {"status": "passed", "message": "API key authenticated."}
            results["model"] = {
                "status": "failed",
                "message": f"Google Server Error (HTTP {status_code}): Gemini servers temporarily unavailable.",
                "model": clean_model,
            }
            results["error_category"] = "Gemini Server Error"
            results["troubleshooting"] = "Google backend servers encountered a temporary issue. Retry in a few seconds."
            return results

        results["auth"] = {"status": "failed", "message": f"HTTP {status_code}: {err_msg}"}
        results["error_category"] = f"HTTP Error {status_code}"
        return results

    except (urllib.error.URLError, TimeoutError) as e:
        reason = getattr(e, "reason", str(e))
        if "timed out" in str(reason).lower():
            results["auth"] = {
                "status": "failed",
                "message": f"Connection Timed Out: Gemini API did not reply within {request_timeout}s.",
            }
            results["error_category"] = "Request Timeout"
            results["troubleshooting"] = f"The connection timed out after {request_timeout}s. Check network stability."
        else:
            results["auth"] = {
                "status": "failed",
                "message": f"Network Error: Unable to complete request to {GEMINI_HOST} ({reason}).",
            }
            results["error_category"] = "Network Error"
        return results
    except Exception as e:
        results["auth"] = {"status": "failed", "message": f"Unexpected Error: {e}"}
        results["error_category"] = "Unexpected Error"
        return results


def verify_gemini_connection(
    api_key: str,
    model_name: str = "gemini-3.8-flash",
    timeout: int = 60,
) -> Tuple[bool, str]:
    """Simplified connection tester for backward-compatibility."""
    diag = run_gemini_diagnostics(api_key, model_name=model_name, connect_timeout=15, request_timeout=timeout)
    if diag["overall_status"] == "Connected":
        return True, f"Connection verified successfully with {model_name}."
    
    # Return specific diagnostic error
    category = diag.get("error_category") or "Connection Error"
    for step in ["auth", "model", "https", "tcp", "dns"]:
        step_info = diag.get(step, {})
        if step_info.get("status") == "failed":
            return False, f"{category}: {step_info.get('message')}"
    return False, f"Connection failed: {diag.get('troubleshooting', 'Unknown error')}"


test_gemini_connection = verify_gemini_connection
