"""Governance rules for respecting privacy and data protection."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fim_agent.core.config import Config
from fim_agent.core.events import Event


# Event types that represent tampering with existing files
TAMPER_EVENTS = {"modify", "delete", "rename", "move_internal", "move_out"}

# Module-level set to track paths that have been seen as sensitive
SENSITIVE_PATHS: set[str] = set()


def _norm_path(path: str | Path | None) -> str:
    """Normalize a path to a canonical string representation."""
    if path is None:
        return ""
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


def is_sensitive(event: Event, config: Optional[Config] = None) -> bool:
    """
    Determine if an event involves sensitive content.
    
    Basic rule: private/secret content is sensitive.
    Optional: treat very high risk score as sensitive too.
    """
    # Basic rule: private/secret content is sensitive
    if event.content_classification in ("private", "secret"):
        return True
    
    # Optional: treat very high risk score as sensitive too
    threshold = getattr(config, "admin_min_risk_score", 80) if config else 80
    if event.risk_score is not None and event.risk_score >= threshold:
        return True
    
    return False


def mark_requires_admin_approval(event: Event, config: Optional[Config] = None) -> Event:
    """
    Admin approval rules:
    
    - A path that becomes sensitive for the first time: first_seen = True, no password required
    - Any later tamper event on the same path: requires_admin_approval = True
    - High-risk tamper events (risk_score >= admin_min_risk_score) always require approval
    - When a path is no longer sensitive, it is removed from the set
    """
    # Default values
    event.requires_admin_approval = False
    event.first_seen = False
    event.admin_approved = None
    
    # If admin approval is globally disabled, no approval needed
    if not config or not getattr(config, "require_admin_for_alerts", True):
        return event
    
    # Only process CREATE and TAMPER_EVENTS
    if event.event_type != "create" and event.event_type not in TAMPER_EVENTS:
        return event
    
    # Normalize path for consistent comparison
    key = _norm_path(event.path)
    
    # Check if path was previously sensitive
    was_sensitive = key in SENSITIVE_PATHS
    # Check if current event is sensitive
    now_sensitive = is_sensitive(event, config)
    
    # For CREATE events: ensure sensitive paths are tracked, but never require approval
    if event.event_type == "create":
        if now_sensitive and not was_sensitive:
            SENSITIVE_PATHS.add(key)  # Track newly sensitive path
            event.first_seen = True
        elif now_sensitive:
            event.first_seen = False  # Already known sensitive path
        else:
            event.first_seen = not was_sensitive  # Not sensitive
        event.requires_admin_approval = False  # CREATE never requires approval
        return event
    
    # Handle TAMPER_EVENTS
    if event.event_type in TAMPER_EVENTS:
        # Check for high-risk tamper event (independent of sensitive path logic)
        admin_min_risk = getattr(config, "admin_min_risk_score", 80)
        is_high_risk = (
            event.risk_score is not None and 
            event.risk_score >= admin_min_risk
        )
        
        # Newly discovered sensitive path (first time) - first_seen optimization
        if now_sensitive and not was_sensitive:
            SENSITIVE_PATHS.add(key)
            event.first_seen = True
            # First tamper on newly sensitive path: only require approval if high-risk
            if is_high_risk:
                event.requires_admin_approval = True
                event.admin_approved = False
            else:
                event.requires_admin_approval = False
            return event
        
        # Subsequent tampering with an already sensitive file
        if was_sensitive:
            event.first_seen = False
            event.requires_admin_approval = True
            event.admin_approved = False
            return event
        
        # High-risk tamper event on non-sensitive path
        if is_high_risk:
            event.first_seen = False
            event.requires_admin_approval = True
            event.admin_approved = False
            return event
        
        # Low-risk tamper event on non-sensitive path
        event.first_seen = False
        event.requires_admin_approval = False
        return event
    
    # If it stopped being sensitive, forget it
    if not now_sensitive and was_sensitive:
        SENSITIVE_PATHS.discard(key)
    
    return event



def is_tamper_event(event: Event) -> bool:
    """
    Determine if an event represents tampering with an existing file.
    
    Returns True for event types that modify or remove existing files:
    - modify, delete, rename, move_internal, move_out
    """
    return event.event_type in TAMPER_EVENTS


def generate_ai_recommendation(event: Event) -> str:
    """
    Return a short human-readable remediation hint for this event.
    
    This is NOT a real AI model, just rule-based logic that provides
    actionable recommendations based on event characteristics.
    """
    recommendations = []
    
    # High priority: Executable/script file drops
    if event.content_flags and "executable_drop" in event.content_flags:
        if event.event_type == "create":
            recommendations.append("🚨 CRITICAL: New executable file detected. Verify source and scan for malware immediately.")
        elif event.event_type == "modify":
            recommendations.append("🚨 CRITICAL: Executable file modified. Check for unauthorized code injection or updates.")
    
    # High priority: Hash changes indicate integrity violation
    if event.hash_changed:
        if event.event_type == "modify":
            recommendations.append("⚠️ INTEGRITY VIOLATION: File hash changed. Compare with baseline to identify unauthorized modifications.")
        elif event.event_type in ("rename", "move_internal"):
            recommendations.append("⚠️ File moved/renamed with hash change. Verify this is expected and not a substitution attack.")
    
    # High priority: Sensitive content tampering
    if event.content_classification in ("private", "secret"):
        if event.event_type in TAMPER_EVENTS:
            if event.requires_admin_approval and not event.admin_approved:
                recommendations.append("🔒 SENSITIVE DATA TAMPERING: Private/secret file modified without admin approval. Review immediately and verify authorization.")
            else:
                recommendations.append("🔒 SENSITIVE DATA: Private/secret file accessed. Ensure proper authorization and audit access logs.")
        elif event.event_type == "create":
            recommendations.append("🔒 SENSITIVE DATA CREATED: New file contains private/secret content. Verify data handling compliance.")
        elif event.event_type == "move_in":
            recommendations.append("🔒 SENSITIVE DATA INGESTED: File with private/secret content moved into monitored area. Verify source and classification.")
    
    # High priority: Suspicious content patterns
    if event.content_flags:
        if "suspicious_base64" in event.content_flags:
            recommendations.append("🔍 SUSPICIOUS: Multiple base64-encoded strings detected. May indicate obfuscated payload - analyze content manually.")
        if any("kw:" in flag for flag in event.content_flags):
            suspicious_kws = [f.replace("kw:", "") for f in event.content_flags if "kw:" in f]
            recommendations.append(f"🔍 SUSPICIOUS KEYWORDS: Detected potentially malicious commands ({', '.join(suspicious_kws[:3])}). Review file content for script injection.")
    
    # Medium priority: High risk scores
    if event.risk_score is not None and event.risk_score >= 80:
        if event.event_type == "create":
            recommendations.append("⚠️ HIGH RISK: New file with elevated risk score. Investigate source and purpose before allowing execution.")
        elif event.event_type == "modify":
            recommendations.append("⚠️ HIGH RISK: File modification with elevated risk score. Verify changes are authorized and expected.")
    
    # Medium priority: Delete events on sensitive files
    if event.event_type == "delete":
        if event.content_classification in ("private", "secret"):
            recommendations.append("🗑️ DATA LOSS RISK: Sensitive file deleted. Check if this is expected or potential data exfiltration/destruction.")
        elif event.risk_score is not None and event.risk_score >= 60:
            recommendations.append("🗑️ HIGH-RISK DELETE: Important file removed. Verify deletion is authorized and check for backup.")
        else:
            recommendations.append("📋 ROUTINE: File deletion detected. Verify this is expected system maintenance.")
    
    # Medium priority: Move/rename events
    if event.event_type in ("rename", "move_internal", "move_out"):
        if event.content_classification in ("private", "secret"):
            recommendations.append("📁 SENSITIVE FILE MOVED: Verify move is authorized and destination is secure.")
        elif event.risk_score is not None and event.risk_score >= 60:
            recommendations.append("📁 HIGH-RISK FILE MOVED: Verify move is expected and not an evasion attempt.")
        else:
            recommendations.append("📋 ROUTINE: File moved/renamed. Verify this is expected system activity.")
    
    # Medium priority: First seen files
    if event.first_seen:
        if event.content_classification in ("private", "secret"):
            recommendations.append("🆕 NEW SENSITIVE FILE: First observation of sensitive content. Classify and apply appropriate access controls.")
        elif event.risk_score is not None and event.risk_score >= 50:
            recommendations.append("🆕 NEW FILE: First observation with moderate risk. Verify source and purpose.")
    
    # Low priority: Admin approval status
    if event.requires_admin_approval:
        if not event.admin_approved:
            recommendations.append("⏳ PENDING APPROVAL: Event requires admin approval. Review and approve if authorized.")
        else:
            recommendations.append("✅ APPROVED: Event has been reviewed and approved by administrator.")
    
    # Low priority: MITRE tags indicate attack techniques
    if event.mitre_tags:
        if "Execution" in event.mitre_tags:
            recommendations.append("⚔️ MITRE Execution: Potential code execution detected. Verify process and command are authorized.")
        if "Defense Evasion" in event.mitre_tags:
            recommendations.append("⚔️ MITRE Defense Evasion: Potential evasion technique detected. Review for anti-forensics activity.")
        if "Persistence" in event.mitre_tags:
            recommendations.append("⚔️ MITRE Persistence: Potential persistence mechanism. Check for unauthorized startup/registry changes.")
        if "Exfiltration" in event.mitre_tags:
            recommendations.append("⚔️ MITRE Exfiltration: File moved outside monitored area. Verify this is not data exfiltration.")
    
    # Default recommendation if nothing specific
    if not recommendations:
        if event.event_type == "create":
            recommendations.append("📋 ROUTINE: New file created. Monitor for suspicious activity.")
        elif event.event_type == "modify":
            recommendations.append("📋 ROUTINE: File modified. Verify changes are expected.")
        else:
            recommendations.append("📋 ROUTINE: File system event detected. No immediate action required.")
    
    # Return the most critical recommendation first, or combine if multiple
    if len(recommendations) == 1:
        return recommendations[0]
    elif len(recommendations) > 1:
        # Prioritize: CRITICAL > INTEGRITY > SENSITIVE > SUSPICIOUS > HIGH RISK > others
        priority_order = ["🚨", "⚠️", "🔒", "🔍", "🗑️", "📁", "🆕", "⏳", "✅", "⚔️", "📋"]
        recommendations.sort(key=lambda r: (
            next((i for i, p in enumerate(priority_order) if r.startswith(p)), len(priority_order)),
            r
        ))
        return recommendations[0] + " " + " | ".join(recommendations[1:3])  # Show top 3
    else:
        return "📋 No specific recommendation. Monitor for patterns."


__all__ = [
    "is_sensitive",
    "is_tamper_event",
    "TAMPER_EVENTS",
    "mark_requires_admin_approval",
    "SENSITIVE_PATHS",
    "_norm_path",
    "generate_ai_recommendation",
]
