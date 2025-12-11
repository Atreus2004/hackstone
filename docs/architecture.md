# FIM Agent Architecture

## Overview

The File Integrity Monitoring (FIM) Agent is a real-time system designed to monitor critical directories, maintain secure baselines of file hashes, and log all changes with precise timestamps and security context.

## Components

### Core Modules

- **watcher.py**: File system watcher using watchdog library for real-time monitoring
- **hasher.py**: Hash computation engine for creating and verifying file baselines
- **events.py**: Event handling and processing for file system changes
- **storage.py**: Tamper-evident storage layer for baselines and logs
- **governance.py**: Governance rules for privacy and data protection compliance

### CLI Module

- **cli/main.py**: Command-line interface entry point

### Web Module

- **web/api.py**: FastAPI REST API endpoints
- **web/templates/timeline.html**: Web-based timeline visualization

## Architecture Diagram

```
┌─────────────┐
│   CLI/Web   │
└──────┬──────┘
       │
┌──────▼──────────────────┐
│      Core Engine        │
├──────────────────────────┤
│  Watcher  │  Hasher     │
│  Events   │  Storage    │
│  Governance              │
└──────────────────────────┘
```

## Data Flow

1. **Monitoring**: Watcher detects file system events (create/modify/delete)
2. **Hashing**: Hasher computes file hashes for comparison
3. **Event Processing**: Events are enriched with security context
4. **Storage**: Events and baselines stored with tamper-evident logging
5. **Alerting**: Security-relevant events trigger alerts

## Security Considerations

- Tamper-evident logging prevents log manipulation
- Hash-based integrity verification
- Governance rules prevent monitoring of sensitive personal data
- SIEM-friendly log format for integration


