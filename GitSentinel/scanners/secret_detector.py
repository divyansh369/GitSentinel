import re
from pathlib import Path
from .entropy import calculate_entropy, is_high_entropy

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key detected", "High"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Token detected", "High"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key detected", "High"),
    (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key detected", "High"),
    (r"-----BEGIN PRIVATE KEY-----", "Private Key detected", "High"),
    (r"password\s*=\s*[\"'].*[\"']", "Hardcoded Password detected", "Medium"),
    (r"api_key\s*=\s*[\"'].*[\"']", "Hardcoded API Key detected", "Medium"),
]

def scan_file(file_path: Path):
    findings = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, line in enumerate(file, start=1):
            line_flagged = False

            # 1. Regex Detection
            for pattern, message, severity in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "filename": file_path.name,
                        "line": line_number,
                        "message": message,
                        "severity": severity
                    })
                    line_flagged = True

            # 2. Shannon Entropy (Only if no regex match found for this line)
            if not line_flagged:
                words = line.split()
                for word in words:
                    clean_word = word.strip("\"' =:;") 
                    
                    if len(clean_word) >= 16 and is_high_entropy(clean_word):
                        e_val = round(calculate_entropy(clean_word), 2)
                        severity = "High" if e_val > 5.0 else ("Medium" if e_val >= 4.0 else "Low")
                        findings.append({
                        "filename": file_path.name,
                        "line": line_number,
                        "message": f"High Entropy String Detected ({clean_word[:10]}...)",
                        "severity": severity,
                        "entropy": round(calculate_entropy(clean_word), 2)
                        })
                        break

    return findings