# Interpreting FIM Agent Output

## Event Types

### File Created
- **What**: New file detected in monitored directory
- **When**: Timestamp of creation
- **Why it matters**: Unauthorized file creation may indicate malware installation or data exfiltration

### File Modified
- **What**: Existing file content changed
- **When**: Timestamp of modification
- **Why it matters**: Unauthorized modifications may indicate:
  - Configuration tampering
  - Data manipulation
  - Malware updates

### File Deleted
- **What**: File removed from monitored directory
- **When**: Timestamp of deletion
- **Why it matters**: Unauthorized deletions may indicate:
  - Data destruction
  - Covering tracks
  - System compromise

## Hash Verification

### Baseline Match
- File hash matches baseline → No integrity issue

### Baseline Mismatch
- File hash differs from baseline → Integrity violation detected
- Indicates unauthorized modification

### Missing Baseline
- File exists but no baseline found → New file or baseline not initialized

## Timeline View

The timeline view shows:
- Chronological sequence of events
- Event type and affected file
- Security context and severity
- Attacker activity patterns
 - Risk scores (rule-based) and AI-like scores

CLI usage:
- `python -m fim_agent.cli.main timeline`
- Optional filters: `--severity high`, `--path-filter watched\\test`, `--from 2025-01-01T00:00:00`, `--to 2025-01-02T00:00:00`

## Log Fields (JSON format)

When `log_format` is `json`, logs include:

### SIEM/Wazuh-friendly fields:
- `source`: "fim_agent" (identifies the log source)
- `category`: "file_integrity" (event category)
- `host`: Current hostname (where the agent is running)
- `rule`: Object with:
  - `id`: 900001 for high-risk events, 900000 for normal events
  - `level`: Alert level (3=low, 7=medium, 12=high/critical)
  - `description`: Human-readable description
- `mitre_techniques`: Array of MITRE ATT&CK techniques/tactics

### Event data fields:
- `timestamp`, `event_type`, `file_path`
- `user`, `user_type`, `process_name`
- `sha256`, `previous_sha256`, `hash_changed`
- `content_classification`, `classification_matches`
- `risk_score`, `ai_classification`, `ai_risk_score`, `ai_risk_reason`
- `severity`, `mitre_tags` (kept for backward compatibility)
- `message`, `alert`
- `requires_admin_approval`, `admin_approved`
- `content_score`, `content_flags`, `ai_recommendation`
- `first_seen`

## Alert Severity Levels

- **Critical**: System files modified, unauthorized executables created
- **High**: Configuration files changed, suspicious patterns detected
- **Medium**: Normal file operations with security implications
- **Low**: Routine changes, expected modifications

## SIEM Integration

Logs are formatted in JSON for SIEM systems:
- Standardized event schema
- Timestamp in ISO 8601 format
- Security context fields
- Hash values for integrity verification
- SIEM-friendly top-level fields (source, category, host, rule, mitre_techniques)

## Example Output

```json
{
  "source": "fim_agent",
  "category": "file_integrity",
  "host": "workstation-01",
  "rule": {
    "id": 900001,
    "level": 12,
    "description": "High-risk file integrity event"
  },
  "mitre_techniques": ["Execution", "Defense Evasion"],
  "timestamp": "2024-01-15T10:30:45.123456",
  "event_type": "modify",
  "file_path": "/etc/passwd",
  "sha256": "abc123...",
  "previous_sha256": "def456...",
  "hash_changed": true,
  "severity": "high",
  "risk_score": 85,
  "alert": true,
  "content_classification": "public",
  "mitre_tags": ["Execution", "Defense Evasion"]
}
```

## Integrating with Wazuh

The FIM agent produces JSON logs that can be ingested by Wazuh or other SIEM systems.

### Log File Location

JSON logs are written to the file specified in `config.log_file` (default: `logs/fim_agent.log`). The logs are line-delimited JSON (one JSON object per line), making them easy to parse.

### Wazuh Configuration

1. **Configure Wazuh to read the log file** (e.g., via Filebeat or Wazuh's log collector):

   Add to your Wazuh agent configuration or Filebeat configuration:
   ```yaml
   # Filebeat example
   filebeat.inputs:
     - type: log
       paths:
         - /path/to/logs/fim_agent.log
       json.keys_under_root: true
       json.add_error_key: true
   ```

2. **Create a Wazuh decoder** (optional, for better parsing):

   ```xml
   <decoder name="fim_agent">
     <prematch>^\s*\{\s*"source"\s*:\s*"fim_agent"</prematch>
   </decoder>

   <decoder name="fim_agent_json">
     <parent>fim_agent</parent>
     <type>json</type>
   </decoder>
   ```

3. **Create a Wazuh rule** to alert on high-risk events:

   ```xml
   <rule id="900001" level="12" overwrite="yes">
     <if_sid>fim_agent</if_sid>
     <match>rule.id:900001</match>
     <description>FIM Agent: High-risk file integrity event detected</description>
     <mitre>
       <id>$(mitre_techniques)</id>
     </mitre>
     <options>no_full_log</options>
   </rule>

   <rule id="900002" level="7" overwrite="yes">
     <if_sid>fim_agent</if_sid>
     <match>rule.id:900000 AND alert:true</match>
     <description>FIM Agent: File integrity alert</description>
   </rule>
   ```

### Key Fields for Wazuh Rules

- `source: "fim_agent"` - Identify FIM agent events
- `category: "file_integrity"` - Filter by category
- `rule.id` - Use 900001 for high-risk, 900000 for normal
- `rule.level` - Alert severity (3=low, 7=medium, 12=high)
- `risk_score` - Numeric risk score (>= 80 is high-risk)
- `alert: true` - Events that triggered alerts
- `mitre_techniques` - MITRE ATT&CK techniques for correlation
- `ai_recommendation` - AI-driven recommendations for investigation
- `content_flags` - Content inspection flags (e.g., "executable_drop")
- `requires_admin_approval` - Events requiring admin approval

### Example Wazuh Query

To find all high-risk executable drops:
```
source:"fim_agent" AND rule.id:900001 AND content_flags:"executable_drop"
```

To find sensitive content events:
```
source:"fim_agent" AND content_classification:("private" OR "secret")
```

