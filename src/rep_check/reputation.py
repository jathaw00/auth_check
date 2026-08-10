import json
import os
import subprocess
import urllib.request
import urllib.error
from datetime import datetime

# ==========================================
# 1. INDIVIDUAL SECURITY ENGINE ADAPTERS
# ==========================================

def check_osv_api(package_name: str, version: str = "") -> list:
    reasons = []
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            for v in data.get("vulns", []):
                cve_id = v.get("id", "Unknown CVE")
                summary = v.get("summary", "No summary provided")
                reasons.append(f"[OSV.dev] Known Vulnerability {cve_id}: {summary}")
    except Exception as e:
        reasons.append(f"[OSV.dev] API unreachable or timed out: {str(e)}")
    
    return reasons

def check_pip_audit(package_name: str) -> list:
    reasons = []
    try:
        # pip-audit checks the PyPI advisory database
        result = subprocess.run(
            ["pip-audit", "--desc", "on", "-f", "json", package_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        reasons.append(f"[pip-audit] {vuln.get('id')}: {vuln.get('description', 'Vulnerability detected')}")
            except json.JSONDecodeError:
                reasons.append(f"[pip-audit] Vulnerabilities detected.")
    except FileNotFoundError:
        reasons.append("[pip-audit] CLI tool not installed in PATH.")
    except subprocess.TimeoutExpired:
        reasons.append("[pip-audit] Scan timed out.")
    except Exception as e:
        reasons.append(f"[pip-audit] Error executing scan: {str(e)}")
        
    return reasons

def check_guarddog(package_name: str) -> list:
    reasons = []
    try:
        # Runs static heuristic rules on package metadata and source
        result = subprocess.run(
            ["guarddog", "pypi", "scan", package_name, "--output-format", "json"],
            capture_output=True,
            text=True,
            timeout=20
        )
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if data.get("issues", 0) > 0:
                    for rule, details in data.get("results", {}).items():
                        if details.get("issues"):
                            reasons.append(f"[GuardDog] Flagged by heuristic rule '{rule}'")
            except json.JSONDecodeError:
                if "issues found" in result.stdout.lower():
                    reasons.append(f"[GuardDog] Suspicious behavior detected in {package_name}")
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        reasons.append("[GuardDog] Scan timed out.")
    except Exception:
        pass
        
    return reasons

def check_socket_dev(package_name: str) -> list:
    reasons = []
    url = f"https://api.socket.dev/v0/pypi/{package_name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AI-Package-Gate/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            score = data.get("score", {})
            supply_chain_score = score.get("supplyChain", 1.0)
            if supply_chain_score < 0.6:
                reasons.append(f"[Socket.dev] Low Supply Chain Health Score: {supply_chain_score*100:.0f}/100")
            if "installScripts" in data.get("capabilities", []):
                reasons.append("[Socket.dev] WARNING: Package executes arbitrary scripts on install.")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            reasons.append("[Socket.dev] Package not found in database (Unverified/New).")
    except Exception:
        pass
        
    return reasons

# ==========================================
# 2. MASTER REPUTATION EVALUATOR
# ==========================================

def check_reputation(package_name: str, version: str = "") -> tuple[int, list]:
    risk_score = 0
    reasons_list = []
    
    # 1. LOCAL DATABASE & AGE CHECK
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, "mock_database.json")
    
    if os.path.exists(db_path):
        with open(db_path, "r") as file:
            reputation_tables = json.load(file)
            pkg_data = reputation_tables.get(package_name, {})
            if pkg_data.get("is_malicious", False):
                risk_score += 80
                reasons_list.append("[Local DB] Flagged as known malware.")
            release_date_str = pkg_data.get("release_date")
            if release_date_str:
                age_in_days = (datetime.now() - datetime.strptime(release_date_str, "%Y-%m-%d")).days
                if age_in_days < 5:
                    risk_score += 35
                    reasons_list.append(f"[Age Check] Package update is only {age_in_days} days old.")
    else:
        return 100, ["CRITICAL: Local reputation tables missing. Failing closed."]

    # 2. OSV.DEV REST API (CVE Check)
    osv_warnings = check_osv_api(package_name, version)
    if osv_warnings:
        risk_score += (40 * len(osv_warnings))
        reasons_list.extend(osv_warnings)

    # 3. PIP-AUDIT (PyPI Advisories)
    pip_audit_warnings = check_pip_audit(package_name)
    if pip_audit_warnings:
        risk_score += 40
        reasons_list.extend(pip_audit_warnings)

    # 4. GUARDDOG (Heuristics / Malware Detection)
    guarddog_warnings = check_guarddog(package_name)
    if guarddog_warnings:
        risk_score += 65
        reasons_list.extend(guarddog_warnings)

    # 5. SOCKET.DEV (Supply Chain & Install Script Check)
    socket_warnings = check_socket_dev(package_name)
    if socket_warnings:
        risk_score += 30
        reasons_list.extend(socket_warnings)

    return min(risk_score, 100), reasons_list

# --- Quick Test Block ---
if __name__ == "__main__":
    print("Running Multi-Engine Security Assessment...\n")
    for pkg in ["requests", "django"]:
        print(f"--- Testing Package: {pkg} ---")
        score, reasons = check_reputation(pkg)
        print(f"Total Risk Score: {score}/100")
        for r in reasons:
            print(f"  -> {r}")
        print()