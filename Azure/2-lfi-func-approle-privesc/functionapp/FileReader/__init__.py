"""
StreamGoat Scenario 2 - Vulnerable Function App
================================================
This function contains intentional vulnerabilities for security training:
- Local File Inclusion (LFI) via 'file' parameter
- Server-Side Request Forgery (SSRF) via 'url' parameter

DO NOT deploy in production!
"""

import azure.functions as func
import os
import logging
import urllib.request
import urllib.error

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('FileReader function processed a request.')

    # Get parameters from query string or request body
    file_path = req.params.get('file')
    ssrf_url = req.params.get('url')
    ssrf_header_name = req.params.get('header_name')
    ssrf_header_value = req.params.get('header_value')

    if not file_path and not ssrf_url:
        try:
            req_body = req.get_json()
            file_path = req_body.get('file')
            ssrf_url = req_body.get('url')
            ssrf_header_name = req_body.get('header_name')
            ssrf_header_value = req_body.get('header_value')
        except ValueError:
            pass

    # SSRF Vulnerability - fetch arbitrary URLs
    if ssrf_url:
        try:
            request = urllib.request.Request(ssrf_url)
            
            # Allow custom headers (useful for MSI token requests)
            if ssrf_header_name and ssrf_header_value:
                request.add_header(ssrf_header_name, ssrf_header_value)
            
            with urllib.request.urlopen(request, timeout=10) as response:
                content = response.read().decode('utf-8')
            
            return func.HttpResponse(
                f"[SSRF RESPONSE]\n\n{content}",
                status_code=200,
                mimetype="text/plain"
            )
        except urllib.error.HTTPError as e:
            return func.HttpResponse(
                f"HTTP Error {e.code}: {e.reason}\n{e.read().decode('utf-8', errors='ignore')}",
                status_code=e.code,
                mimetype="text/plain"
            )
        except urllib.error.URLError as e:
            return func.HttpResponse(
                f"URL Error: {str(e.reason)}",
                status_code=500,
                mimetype="text/plain"
            )
        except Exception as e:
            return func.HttpResponse(
                f"SSRF Error: {str(e)}",
                status_code=500,
                mimetype="text/plain"
            )

    # LFI Vulnerability - read arbitrary files
    if file_path:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            return func.HttpResponse(
                f"[FILE CONTENT: {file_path}]\n\n{content}",
                status_code=200,
                mimetype="text/plain"
            )
        except FileNotFoundError:
            return func.HttpResponse(
                f"File not found: {file_path}",
                status_code=404,
                mimetype="text/plain"
            )
        except PermissionError:
            return func.HttpResponse(
                f"Permission denied: {file_path}",
                status_code=403,
                mimetype="text/plain"
            )
        except Exception as e:
            return func.HttpResponse(
                f"Error reading file: {str(e)}",
                status_code=500,
                mimetype="text/plain"
            )

    # Default response - help message
    help_text = """
╔═══════════════════════════════════════════════════════════════╗
║           StreamGoat File Reader Service v1.0                 ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  File Read (LFI):                                             ║
║    GET /api/FileReader?file=<path>                            ║
║                                                               ║
║  URL Fetch (SSRF):                                            ║
║    GET /api/FileReader?url=<url>                              ║
║    GET /api/FileReader?url=<url>&header_name=X&header_value=Y ║
║                                                               ║
║  Examples:                                                    ║
║    ?file=/etc/hostname                                        ║
║    ?file=/proc/self/environ                                   ║
║    ?url=http://example.com                                    ║
║                                                               ║
║  Status: OK                                                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """

    return func.HttpResponse(
        help_text,
        status_code=200,
        mimetype="text/plain"
    )
