import json
import os
from datetime import datetime

def check_reputation(package_name):
    """
    Checks package against reputation tables and release age.
    Returns: Risk value (int), List of warning reasons (list)
    """
    risk_score = 0
    reasons_list = []
    
    # Locate and load the mock database
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, "mock_database.json")
    
    if not os.path.exists(db_path):
        # FAIL CLOSED: If we can't verify reputation, we do not allow installation.
        return 100, ["CRITICAL: Reputation tables missing. Failing closed to prevent unsafe execution."]
        
    with open(db_path, "r") as file:
        reputation_tables = json.load(file)
        
    # If the package isn't in our database at all
    if package_name not in reputation_tables:
        return 10, ["Package unknown: Not found in reputation tables."]
        
    pkg_data = reputation_tables[package_name]
    
    # Check 1: Reputation Tables (Is it flagged malware?)
    if pkg_data.get("is_malicious", False):
        risk_score += 80
        reasons_list.append("Failed reputation check: Flagged as known malware.")
        
    # Check 2: Release Age 
    release_date_str = pkg_data.get("release_date")
    if release_date_str:
        release_date = datetime.strptime(release_date_str, "%Y-%m-%d")
        current_date = datetime.now()
        
        # Calculate how many days the package has been live
        age_in_days = (current_date - release_date).days
        acceptable_age = 5  # 5-day cooldown period
        
        if age_in_days < acceptable_age:
            risk_score += 45
            reasons_list.append(f"Release age warning: Update is only {age_in_days} days old (Requires {acceptable_age} days).")
            
    # Ensure the Risk value doesn't exceed 100
    risk_score = min(risk_score, 100)
    
    return risk_score, reasons_list

# --- Quick Test Block ---
if __name__ == "__main__":
    test_packages = ["requests", "malicious-pkg", "sus-pkg", "unknown-pkg"]
    for pkg in test_packages:
        score, reasons = check_reputation(pkg)
        print(f"Package: {pkg} | Risk Value: {score}")
        for r in reasons:
            print(f"  - {r}")