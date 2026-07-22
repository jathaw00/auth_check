import sys
import subprocess
import sys
import subprocess
from src.scanners.scan import run_payload_scan
from src.rep_check.reputation import check_reputation
from src.utils.logger import log_event

def parse_command_tokens(args: list[str]) -> tuple[bool, str | None]:
    """
    Parses the raw command tokens to determine if this is an installation 
    and attempts to extract the target package name.
    """
    # Common commands that trigger an installation or update
    install_triggers = {'install', 'i', 'add', 'update'}
    
    is_install_event = False
    target_package = None
    
    for i, token in enumerate(args):
        if token.lower() in install_triggers:
            is_install_event = True
            
            # Look ahead for the first token that isn't a flag (doesn't start with '-')
            # This is a rudimentary way to grab the package name (e.g., pip install -U requests)
            for j in range(i + 1, len(args)):
                if not args[j].startswith('-'):
                    target_package = args[j]
                    break
            break # Stop parsing once we find the install trigger and package
            
    return is_install_event, target_package

def execute_passthrough(args: list[str]):
    """
    Phase 5: Transparently passes the command back to the system shell.
    """
    print(f"\n[System] Executing pass-through: {' '.join(args)}")
    
    try:
        # Run the command and route output directly to the user's terminal
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
    except FileNotFoundError:
        print(f"\n[Error] Command not found: {args[0]}")
        sys.exit(1)

def trigger_warning_sequence(package_name: str, reasons_list: list) -> bool:
    """
    Phase 4: Displays the warning, prompts for an override code, and logs the event.
    Returns True if overridden, exits the program if blocked.
    """
    print(f"\n🚨 WARNING SEQUENCE INITIATED")
    for reason in reasons_list:
        print(f"   - {reason}")
        
    override_code = "admin123"  # Your configured override token
    user_input = input("\nEnter security override token to proceed (or press Enter to abort): ")
    
    # Combine reasons into a single string for the log
    reason_str = " | ".join(reasons_list)
    
    if user_input == override_code:
        print("   ✅ OVERRIDE ACCEPTED. Proceeding to installation...")
        log_event(package_name, reason_str, "Action: OVERRIDDEN")
        return True
    else:
        print("   ❌ OVERRIDE DENIED. Installation safely aborted.")
        log_event(package_name, reason_str, "Action: BLOCKED")
        sys.exit(1)

def main():
    # sys.argv[0] is the name of our script (interceptor.py), so we slice it off
    raw_args = sys.argv[1:]
    
    if not raw_args:
        print("Usage: python interceptor.py <package-manager> <command> [args...]")
        print("Example: python interceptor.py npm install requests")
        sys.exit(1)

    # --- PHASE 1: INTERCEPTION ---
    is_install, package_name = parse_command_tokens(raw_args)

    if is_install and package_name:
        print(f"\n🛡️  [Interceptor] Installation detected for target: '{package_name}'")
        print("   Routing to Phase 2: Payload Scan...")
        
        # --- PHASE 2: PAYLOAD SCAN ---
        is_safe, scan_message = run_payload_scan()
        
        if not is_safe:
            trigger_warning_sequence(package_name, [scan_message])
            
        print("   Payload scan clean. Passing to Phase 3: Reputation Check...")
        
        # --- PHASE 3: REPUTATION CHECK ---
        risk_value, reputation_reasons = check_reputation(package_name)
        acceptable_rep = 70
        
        if risk_value >= acceptable_rep:
            reputation_reasons.insert(0, f"Unacceptable Risk Value ({risk_value}/100)")
            trigger_warning_sequence(package_name, reputation_reasons)
            
        print("   Reputation acceptable. Passing to installation...")
        execute_passthrough(raw_args)
        
    else:
        execute_passthrough(raw_args)
    

if __name__ == "__main__":
    main()