# FIM Agent

A file integrity monitoring (FIM) agent that tracks changes, calculates risk scores, and can expose results via a CLI or web API.

## Getting started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy and customize the configuration:
   ```bash
   cp config/config_example.yaml config/config.yaml
   # Edit config/config.yaml to match your environment
   ```
3. Run the agent from the command line:
   ```bash
   python -m fim_agent.cli.main --config config/config.yaml
   ```

## JSON logging

All application logs can be emitted as JSON Lines (one JSON object per line) through configuration alone. Update your `config/config.yaml` with:

```yaml
log_file: "./logs/fim_agent.jsonl"
log_format: "json"
```

Example commands to enforce JSON logging:

- **Linux/macOS (bash):**
  ```bash
  cp config/config_example.yaml config/config.yaml
  perl -0777 -i -pe 's|log_file:.*|log_file: "./logs/fim_agent.jsonl"|' config/config.yaml
  perl -0777 -i -pe 's|log_format:.*|log_format: "json"|' config/config.yaml
  python -m fim_agent.cli.main --config config/config.yaml
  ```

- **Windows (PowerShell):**
  ```powershell
  Copy-Item config/config_example.yaml config/config.yaml
  (Get-Content config/config.yaml) -replace 'log_file:.*', 'log_file: "./logs/fim_agent.jsonl"' -replace 'log_format:.*', 'log_format: "json"' | Set-Content config/config.yaml
  python -m fim_agent.cli.main --config config/config.yaml
  ```

These settings apply to both stdout and the log file, so forwarded logs will already be JSON.
