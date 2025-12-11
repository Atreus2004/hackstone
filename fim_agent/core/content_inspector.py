"""Content inspection for file integrity monitoring."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from fim_agent.core.events import Event

# Maximum file size to inspect (512KB)
MAX_INSPECT_SIZE = 512 * 1024

# Classification keywords
SECRET_KEYWORDS = [
    "credit card", "card number", "iban", "cvv", "cvc",
    "password", "passwort", "parol", "pin code", "api_key", "secret_key",
    "private key", "ssh key", "access token", "bearer token",
    "aws_secret", "azure_key", "gcp_key",
]

PRIVATE_KEYWORDS = [
    "passport", "pasport", "id number", "serial number",
    "salary", "maas", "phone number", "telefon", "email address",
    "social security", "ssn", "tax id", "national id",
    "bank account", "account number",
]

INTERNAL_KEYWORDS = [
    "internal use only", "for internal use", "confidential",
    "restricted", "do not distribute", "proprietary",
    "company confidential", "not for public",
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1",  # PowerShell
    ".bat", ".cmd", ".com",  # Windows batch/command
    ".vbs", ".vbe", ".js", ".jse",  # Scripts
    ".exe", ".dll", ".sys", ".scr", ".msi", ".msix",  # Executables
    ".docm", ".xlsm", ".pptm",  # Macro-enabled Office
    ".jar", ".class",  # Java
    ".sh", ".bash",  # Shell scripts
}

# Suspicious keywords to detect
SUSPICIOUS_KEYWORDS = [
    ("invoke-webrequest", "PowerShell web request"),
    ("downloadfile(", "File download function"),
    ("new-object system.net.webclient", "WebClient object creation"),
    ("start-process", "Process execution"),
    ("add-mppreference", "Windows Defender modification"),
    ("reg add", "Registry modification"),
    ("schtasks /create", "Scheduled task creation"),
    ("vssadmin delete shadows", "Volume shadow copy deletion"),
    ("cipher /w:", "Secure deletion"),
    ("powershell -encodedcommand", "Encoded PowerShell"),
    ("powershell -enc", "Encoded PowerShell (short)"),
    ("certutil -decode", "Base64 decoding utility"),
    ("bitsadmin", "Background Intelligent Transfer Service"),
    ("wmic process call create", "Process creation via WMI"),
    ("net user", "User account manipulation"),
    ("net localgroup", "Group manipulation"),
]

# Base64 pattern (simplified - looks for long base64-like strings)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')


def classify_text(text: str) -> Tuple[str, List[str]]:
    """
    Return (classification, matches).
    classification ∈ {"secret", "private", "internal", "public"}.
    matches is a list of matched keyword tags.
    """
    text_lower = text.lower()
    matches: List[str] = []
    classification = "public"
    
    # Check for secret keywords (highest priority)
    for keyword in SECRET_KEYWORDS:
        if keyword.lower() in text_lower:
            matches.append(f"secret:{keyword}")
            classification = "secret"
    
    # Check for private keywords (if not already secret)
    if classification == "public":
        for keyword in PRIVATE_KEYWORDS:
            if keyword.lower() in text_lower:
                matches.append(f"private:{keyword}")
                if classification == "public":
                    classification = "private"
    
    # Check for internal keywords (if not already secret or private)
    if classification == "public":
        for keyword in INTERNAL_KEYWORDS:
            if keyword.lower() in text_lower:
                matches.append(f"internal:{keyword}")
                if classification == "public":
                    classification = "internal"
    
    return classification, matches


@dataclass
class ContentAnalysis:
    """Result of content inspection analysis."""
    score: int
    flags: List[str]
    classification: str = "public"  # Classification: public, internal, private, secret
    classification_matches: List[str] = None  # Keywords that matched


def analyze_file_content(path: Path, event: Event) -> ContentAnalysis:
    """
    Analyze file content for suspicious patterns.
    
    Returns ContentAnalysis with score and flags, even on errors.
    Never executes the file, only performs static inspection.
    """
    score = 0
    flags: List[str] = []
    classification = "public"
    classification_matches: List[str] = []
    
    try:
        # Check file extension
        ext = path.suffix.lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            score += 15
            flags.append(f"extension:{ext}")
        
        # Check file size before reading
        try:
            file_size = path.stat().st_size
            if file_size > MAX_INSPECT_SIZE:
                # File too large, skip content inspection but keep extension check
                return ContentAnalysis(score=score, flags=flags, classification=classification, classification_matches=classification_matches)
        except (OSError, PermissionError):
            # Can't read file, return what we have
            return ContentAnalysis(score=score, flags=flags, classification=classification, classification_matches=classification_matches)
        
        # Read file content (text mode with error handling)
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (UnicodeDecodeError, OSError, PermissionError):
            # Try binary mode and decode with errors ignored
            try:
                with path.open("rb") as f:
                    raw_content = f.read(MAX_INSPECT_SIZE)
                    content = raw_content.decode("utf-8", errors="ignore")
            except (OSError, PermissionError):
                return ContentAnalysis(score=score, flags=flags, classification=classification, classification_matches=classification_matches)
        
        content_lower = content.lower()
        
        # Classify content based on keywords
        classification, classification_matches = classify_text(content)
        # Update the outer scope variables
        classification = classification
        classification_matches = classification_matches
        
        # Check for suspicious keywords
        for keyword, description in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in content_lower:
                score += 10
                flags.append(f"kw:{keyword}")
        
        # Detect base64-like strings
        base64_matches = BASE64_PATTERN.findall(content)
        if len(base64_matches) >= 3:  # Multiple long base64 strings
            score += 20
            flags.append("suspicious_base64")
        elif len(base64_matches) >= 1:
            # Single long base64 string - less suspicious but still notable
            score += 5
            flags.append("base64_detected")
        
        # Check for very long lines (potential obfuscation)
        lines = content.split('\n')
        long_lines = [line for line in lines if len(line) > 1000]
        if len(long_lines) > 0:
            score += 5
            flags.append("long_lines")
        
        # Check for high entropy (potential encryption/encoding)
        # Simple heuristic: count unique characters vs total
        if len(content) > 100:
            unique_chars = len(set(content))
            total_chars = len(content)
            entropy_ratio = unique_chars / total_chars if total_chars > 0 else 0
            if entropy_ratio > 0.7:  # High entropy
                score += 10
                flags.append("high_entropy")
        
    except Exception:
        # On any error, return what we have so far
        pass
    
    return ContentAnalysis(
        score=min(score, 100),
        flags=flags,
        classification=classification,
        classification_matches=classification_matches,
    )


__all__ = ["ContentAnalysis", "analyze_file_content", "classify_text"]

