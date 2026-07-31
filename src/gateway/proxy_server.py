import sys
import os
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
import re

# --- PATH FIX ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, project_root)

from src.scanners.scan import run_payload_scan
from src.rep_check.reputation import check_reputation
from src.utils.logger import log_event

class SecurityProxyHandler(BaseHTTPRequestHandler):
    
    def extract_pypi_package(self, path: str) -> str | None:
        """
        Parses PyPI download URLs to extract the target package name.
        Example path: /simple/requests/ -> 'requests'
        """
        # PyPI standard paths generally use /simple/<package-name>/
        match = re.search(r'/simple/([^/]+)', path)
        if match:
            return match.group(1).lower()
        return None

    def evaluate_security_gate(self, package_name: str) -> bool:
        """
        Runs Phase 2 (Static Scan) and Phase 3 (Reputation Check).
        Returns True if safe to pass, False if blocked.
        """
        print(f"\n🛡️  [Proxy Intercept] Outgoing download request for package: '{package_name}'")
        
        # --- PHASE 2: STATIC SCAN ---
        print("   Running Phase 2: Static Payload Scan...")
        is_safe, scan_msg = run_payload_scan()
        if not is_safe:
            print(f"🚨 BLOCKED BY GATEWAY (Phase 2): {scan_msg}")
            log_event(package_name, scan_msg, "Action: BLOCKED BY PROXY")
            return False

        # --- PHASE 3: REPUTATION CHECK ---
        print("   Running Phase 3: Reputation Check...")
        risk_value, reasons = check_reputation(package_name)
        acceptable_rep = 70
        
        if risk_value >= acceptable_rep:
            reason_str = " | ".join(reasons)
            print(f"🚨 BLOCKED BY GATEWAY (Phase 3): Unacceptable Risk Score ({risk_value}/100)")
            for r in reasons:
                print(f"   - {r}")
            log_event(package_name, reason_str, "Action: BLOCKED BY PROXY")
            return False

        print("   ✅ Safety checks passed. Authorizing connection...")
        return True
    
    def do_CONNECT(self):
        """
        Handles HTTPS tunnel requests from pip.
        """
        # self.path will look like "pypi.org:443" or "files.pythonhosted.org:443"
        print(f"\n🔗 [Proxy Tunnel] Encrypted HTTPS tunnel requested to: {self.path}")
        
        # Respond to pip that the tunnel is open
        self.send_response(200, "Connection Established")
        self.end_headers()
        
        # Note: In a full production proxy (like Socket Firewall), this is where 
        # Man-in-the-Middle (MITM) SSL decryption happens to inspect the payload.
        # For our lightweight prototype, we allow the tunnel to open after logging it!

    def do_GET(self):
        """
        Intercepts standard HTTP GET requests and forwards them correctly.
        """
        package_name = self.extract_pypi_package(self.path)
        
        if package_name:
            if not self.evaluate_security_gate(package_name):
                # Return HTTP 403 Forbidden to the package manager
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"403 Forbidden: Blocked by AI-Package-Gate Security Policy\n")
                return

        # Correctly reconstruct the destination URL whether pip sends a full URL or a relative path
        try:
            if self.path.startswith("http://") or self.path.startswith("https://"):
                url = self.path
            elif self.path.startswith("/simple") or self.path.startswith("/pypi"):
                url = f"http://pypi.org{self.path}"
            else:
                url = f"http://files.pythonhosted.org{self.path}"

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
        # Silences the default noisy HTTP server console output
        pass

def start_proxy(port=8080):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, SecurityProxyHandler)
    print(f"🚀 AI-Package-Gate Network Proxy active on http://127.0.0.1:{port}")
    print("   Waiting for outgoing package manager traffic... (Press Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n Shutting down proxy server.")
        httpd.server_close()

if __name__ == "__main__":
    start_proxy()