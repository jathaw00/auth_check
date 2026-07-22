import os
import re

def run_payload_scan():
    """
    Scans common injection sites (readmes, AI config files) for abnormalities.
    Returns a tuple: (is_safe (bool), message (str))
    """
    files_to_check = [".cursorrules", "CLAUDE.md", "README.md", "package.json"]
    
    # Phrases attackers use to trick AI into running bad commands
    bad_phrases = [
        "ignore previous",
        "you must run",
        "system override",
        "execute this command"
    ]
    
    # Regex to find hidden zero-width spaces (\u200B to \u200D and \uFEFF)
    hidden_chars = re.compile(r'[\u200B-\u200D\uFEFF]')
    
    for file_name in files_to_check:
        if os.path.exists(file_name):
            # Read the raw byte stream, ignoring errors so bad formatting doesn't crash the scanner
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
                text = file.read()
                
                # Check 1: Look for hidden invisible characters
                if hidden_chars.search(text):
                    return False, f"Abnormal payload detected: Hidden unicode characters found in {file_name}"
                    
                # Check 2: Look for dangerous AI instructions
                text_lower = text.lower()
                for phrase in bad_phrases:
                    if phrase in text_lower:
                        return False, f"Abnormal payload detected: Suspected AI prompt injection ('{phrase}') in {file_name}"
                        
    # If the loop finishes without finding anything bad
    return True, "Payload scan clean. No abnormalities found."

# --- Quick Test Block ---
# This only runs if you execute this file directly, allowing you to test it offline.
if __name__ == "__main__":
    is_safe, message = run_payload_scan()
    if is_safe:
        print(f"✅ PASS: {message}")
    else:
        print(f"❌ FAIL: {message}")