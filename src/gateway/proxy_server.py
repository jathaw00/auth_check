import sys
import os
import urllib.request
import socket
import select
from http.server import HTTPServer, BaseHTTPRequestHandler
import re

# --- PATH FIX ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, project_root)

from src.scanners.scan import inspect_package_bytes
from src.rep_check.reputation import check_reputation

class SecurityProxyHandler(BaseHTTPRequestHandler):
    
    def extract_pypi_package(self, path: str) -> str | None:
        """Parses PyPI download URLs to extract the target package name."""
        match = re.search(r'/simple/([^/]+)', path)
        if match:
            return match.group(1).lower()
        return None

    def evaluate_reputation_gate(self, package_name: str) -> bool:
        """Runs Phase 3 (Reputation Check) when pip asks for the package index."""
        print(f"\n🛡️  [Phase 3] Reputation Check for package: '{package_name}'")
        risk_value, reasons = check_reputation(package_name)
        acceptable_rep = 70
        
        if risk_value >= acceptable_rep:
            print(f"🚨 BLOCKED BY GATEWAY (Phase 3): Unacceptable Risk Score ({risk_value}/100)")
            for r in reasons:
                print(f"   - {r}")
            return False

        print("   ✅ Reputation checks passed. Allowing index lookup...")
        return True

    def do_CONNECT(self):
        """Handles HTTPS tunnel requests from pip."""
        host, port = self.path.split(":")
        port = int(port)
        try:
            upstream_socket = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            sockets = [self.connection, upstream_socket]
            while True:
                readable, _, _ = select.select(sockets, [], sockets, 10)
                if not readable:
                    break
                for sock in readable:
                    data = sock.recv(8192)
                    if not data:
                        return
                    if sock is self.connection:
                        upstream_socket.sendall(data)
                    else:
                        self.connection.sendall(data)
        except Exception:
            return
        finally:
            try:
                upstream_socket.close()
            except Exception:
                pass

    def do_GET(self):
        """Intercepts unencrypted HTTP GET requests for scanning."""
        
        # Determine the target URL
        if self.path.startswith("http://") or self.path.startswith("https://"):
            url = self.path
        elif self.path.startswith("/simple") or self.path.startswith("/pypi"):
            url = f"http://pypi.org{self.path}"
        else:
            url = f"http://files.pythonhosted.org{self.path}"

        filename = url.split("/")[-1]

        # --- ROUTE A: PACKAGE FILE DOWNLOAD (Run Phase 2 Payload Scan) ---
        if filename.endswith(".whl") or filename.endswith(".tar.gz") or filename.endswith(".zip"):
            print(f"\n📦 [Phase 2] Intercepted payload download: {filename}")
            print("   Buffering file into memory for static malware scan...")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AI-Package-Gate-Proxy/1.0"})
                with urllib.request.urlopen(req) as response:
                    # 1. Download the bytes completely into RAM
                    file_bytes = response.read()
                    
                    # 2. Run the payload scanner
                    is_safe, msg = inspect_package_bytes(file_bytes, filename)
                    
                    if not is_safe:
                        print(f"🚨 BLOCKED BY GATEWAY (Phase 2): {msg}")
                        self.send_response(403)
                        self.send_header("Content-type", "text/plain")
                        self.end_headers()
                        self.wfile.write(f"403 Forbidden: Malware signature detected in payload\nDetail: {msg}\n".encode())
                        return
                        
                    # 3. Safe! Send the bytes to pip
                    print("   ✅ Payload scan clear. Forwarding bytes to package manager...")
                    self.send_response(response.status)
                    for key, val in response.getheaders():
                        self.send_header(key, val)
                    self.end_headers()
                    self.wfile.write(file_bytes)
                    return
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"502 Bad Gateway: {str(e)}\n".encode("utf-8"))
                return

        # --- ROUTE B: PACKAGE INDEX LOOKUP (Run Phase 3 Reputation Scan) ---
        package_name = self.extract_pypi_package(self.path)
        if package_name:
            if not self.evaluate_reputation_gate(package_name):
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"403 Forbidden: Blocked by AI-Package-Gate Reputation Policy\n")
                return

        # Default passthrough for any other HTTP traffic (API calls, simple index HTML, etc.)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AI-Package-Gate-Proxy/1.0"})
            with urllib.request.urlopen(req) as response:
                self.send_response(response.status)
                for key, val in response.getheaders():
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(response.read())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"502 Bad Gateway: {str(e)}\n".encode("utf-8"))

    def log_message(self, format, *args):
        pass

def start_proxy(port=8080):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, SecurityProxyHandler)
    print(f"🚀 AI-Package-Gate Network Proxy active on http://127.0.0.1:{port}")
    print("   Waiting for outgoing package manager traffic... (Press Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down proxy server.")
        httpd.server_close()

if __name__ == "__main__":
    start_proxy()