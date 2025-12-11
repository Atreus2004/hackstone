# FIM Agent Usage Guide

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Copy and configure the example config:
```bash
cp config/config_example.yaml config/config.yaml
# Edit config.yaml with your settings
```

## Running the Agent

### CLI Mode

Run the agent from the command line:
```bash
python -m fim_agent.cli.main
```

### Timeline view (attacker/system activity)

After the agent has run and generated events, view them chronologically:
```bash
python -m fim_agent.cli.main timeline
python -m fim_agent.cli.main timeline --severity high
python -m fim_agent.cli.main timeline --path-filter watched\\test
python -m fim_agent.cli.main timeline --from 2025-01-01T00:00:00 --to 2025-01-02T00:00:00
```
Output format:
```
timestamp | event_type | severity | path | risk_score | ai_risk_score | message
```

### Web Interface

Start the web API server:
```bash
python -m fim_agent.cli.main --config config\config.yaml serve-web
python -m fim_agent.cli.main --config config\config.yaml serve-web --host 127.0.0.1 --port 8080
```

The web server provides a REST API for accessing FIM events and statistics. Once started, you can:

- Access the API documentation at `http://localhost:8000/docs` (Swagger UI)
- Query events via `http://localhost:8000/api/events`
- View statistics at `http://localhost:8000/api/stats/summary`

#### API Endpoints

**GET /api/events**
- Query parameters:
  - `severity`: Filter by severity (low/medium/high)
  - `classification`: Filter by content_classification
  - `min_risk`: Minimum risk_score
  - `limit`: Maximum number of events (default: 100, max: 1000)
  - `offset`: Number of events to skip (default: 0)
- Returns: JSON list of events with pagination info
- Example: `http://localhost:8000/api/events?severity=high&limit=50`

**GET /api/events/{event_id}**
- Returns: Full details for a single event by database ID
- Example: `http://localhost:8000/api/events/123`

**GET /api/stats/summary**
- Returns: High-level statistics including:
  - `total_events`: Total number of events
  - `total_alerts`: Number of alert events
  - `counts_by_severity`: Breakdown by severity level
  - `counts_by_event_type`: Breakdown by event type (create/modify/delete/etc.)
  - `counts_by_classification`: Breakdown by content classification

**GET /api/stats/risk_pie**
- Returns: Risk score distribution in buckets:
  - `low`: 0-29
  - `medium`: 30-59
  - `high`: 60-79
  - `critical`: 80+
- Useful for pie chart visualization

**GET /**
- Returns: API information and available endpoints

## Configuration

Edit `config/config.yaml` to specify:
- Directory to monitor
- Hash algorithm
- Excluded paths and patterns
- Logging settings
- Alert configuration

## Monitoring a Directory

The agent will:
1. Build an initial baseline of file hashes
2. Monitor for changes in real-time
3. Log all create/modify/delete events
4. Generate alerts for security-relevant changes

## Viewing Results

- **CLI**: Check log files specified in configuration
- **Web**: Access timeline view at `http://localhost:8000/timeline`
- **SIEM**: Logs are formatted for SIEM integration (see "Integrating with Wazuh" in `docs/interpreting_output.md`)

## Log Formats

The agent supports three log formats (configured via `log_format` in `config.yaml`):

- **json**: Standard JSON format with SIEM/Wazuh-friendly fields (recommended for SIEM integration)
- **wazuh**: Wazuh-specific nested JSON format
- **text**: Human-readable text format

When using `json` format, logs are written as line-delimited JSON (one JSON object per line) to the file specified in `config.log_file`.

## Troubleshooting

- Ensure the monitored directory exists and is accessible
- Check log files for errors
- Verify configuration file syntax (YAML)

