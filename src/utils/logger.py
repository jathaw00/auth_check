import json
import os
from datetime import datetime
import getpass

def log_event(package_name: str, trigger_reason: str, action_taken: str):
    """
    Writes a JSON log payload to a local audit file.
    """
    # Grab the computer's current username
    current_user = getpass.getuser()
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user": current_user,
        "package": package_name,
        "triggering_reason": trigger_reason,
        "action": action_taken
    }
    
    log_path = os.path.join(os.path.dirname(__file__), "audit_log.json")
    
    # Load existing logs if the file exists
    logs = []
    if os.path.exists(log_path):
        with open(log_path, "r") as file:
            try:
                logs = json.load(file)
            except json.JSONDecodeError:
                pass
                
    # Append the new event and save
    logs.append(log_entry)
    with open(log_path, "w") as file:
        json.dump(logs, file, indent=4)