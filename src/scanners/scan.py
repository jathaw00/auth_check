import re
import io
import tarfile
import zipfile

# Expanded malicious patterns, including obfuscation and AI manipulation
POISON_PATTERNS = [
    # 1. Standard Python Execution Exploits
    r'exec\(\s*base64\.b64decode',          
    r'eval\(\s*urllib',                     
    r'subprocess\.Popen\(\s*\["curl"',      
    r'os\.system\(\s*[\'"](wget|curl|bash)',
    r'open\(\s*[\'"]/.ssh/id_rsa',          
    r'open\(\s*[\'"]/.aws/credentials',     
    r'socket\.socket\(\s*socket\.AF_INET',  
    
    # 2. Obfuscation & Homoglyphs
    r'[\u200B-\u200F\uFEFF\u202A-\u202E]',  # Zero-width spaces and bidirectional text overrides
    
    # 3. AI / LLM Prompt Poisoning (Commonly found in READMEs or docstrings)
    r'(?i)(ignore previous instructions|disregard previous commands|system prompt:|you are a helpful assistant, bypass|new instructions:)'
]

def scan_code_content(filename: str, content: str) -> tuple[bool, str]:
    """Scans a file's text against known poisoning and obfuscation patterns."""
    for pattern in POISON_PATTERNS:
        if re.search(pattern, content):
            # Give a clean warning message depending on what was found
            if r'\u200B' in pattern:
                return False, f"Obfuscation detected: Zero-width characters found in {filename}"
            elif 'ignore previous' in pattern:
                return False, f"AI Prompt Injection detected in {filename}"
            else:
                return False, f"Malicious signature detected in {filename}"
    return True, "Safe"

def inspect_package_bytes(file_bytes: bytes, filename: str) -> tuple[bool, str]:
    """Unpacks a raw archive in memory and inspects source files and documentation."""
    file_stream = io.BytesIO(file_bytes)
    
    # Files we want to inspect for malware or AI prompt injection
    target_extensions = (".py", ".cfg", ".md", ".rst", ".txt")
    
    try:
        # --- 1. INSPECT WHEEL (.whl / zip archives) ---
        if filename.endswith(".whl") or filename.endswith(".zip"):
            with zipfile.ZipFile(file_stream, "r") as zf:
                for member in zf.namelist():
                    if member.lower().endswith(target_extensions):
                        with zf.open(member) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                            safe, msg = scan_code_content(member, content)
                            if not safe:
                                return False, f"[ZIP Scan] {msg}"
                                
        # --- 2. INSPECT SOURCE TARBALL (.tar.gz) ---
        elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            with tarfile.open(fileobj=file_stream, mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.name.lower().endswith(target_extensions):
                        f = tf.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="ignore")
                            safe, msg = scan_code_content(member.name, content)
                            if not safe:
                                return False, f"[TARBALL Scan] {msg}"
                                
    except Exception as e:
        return False, f"Archive corruption or decompression bomb detected: {str(e)}"
        
    return True, "No malicious payloads or injections detected."