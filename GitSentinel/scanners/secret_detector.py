import re
from pathlib import Path
from .entropy import *

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[0-9a-zA-Z]{36}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"sk_live_[0-9a-zA-Z]{24}",
    r"-----BEGIN PRIVATE KEY-----",
    r"password\s*=\s*[\"'].*[\"']",
    r"api_key\s*=\s*[\"'].*[\"']",
]


def scan_file(file_path: Path):
    finding = []

    with open(file_path, "r") as file:
        lines = file.readlines()
        for line_number, line in enumerate(lines, start=1):

            # regex detection
            for pattern in SECRET_PATTERNS:
                if re.search(pattern, line):
                    finding.append(
                        {
                            "filename": file_path.name,
                            "line": line_number,
                            "pattern": pattern,
                        }
                    )

            # shannon entropy
            words = line.split()
            for word in words:
                if len(word) > 20 and is_high_entropy(word):
                    finding.append(
                        {
                            "filename": file_path.name,
                            "line": line_number,  
                            "entropy": round(
                                calculate_entropy(word), 2
                            ),
                            "word": word, 
                        }
                    )

    return finding
