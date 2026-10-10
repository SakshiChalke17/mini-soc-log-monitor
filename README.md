###Mini SOC LOG Monitor

A Python-based security log monitoring tool that analyses authentication logs, detects suspicious login activity, and generates structured security alerts.

## Features

- **Log parsing:** Extracts timestamps, event types, usernames, and IP addresses from authentication logs.
- **Brute-force detection:** Identifies repeated failed login attempts within a configurable time window.
- **Successful login after failures:** Detects successful authentication following repeated failed login attempts.
- **Unknown-user detection:** Flags login activity involving usernames outside a configured list of known users.
- **Severity classification:** Assigns severity levels to security alerts.
- **Alert summaries:** Summarises detected alerts by severity and alert type.
- **JSON alert output:** Saves generated alerts in JSON format.
- **Input validation:** Handles malformed log entries and invalid fields.
- **Automated tests:** Uses pytest to test parsing, detection rules, and alert output.

## Technologies Used

- Python
- pytest
- JSON
- Git and GitHub

## Project Structure

```text
mini-soc-log-monitor/
├── sample_logs/
│   └── auth.log
├── tests/
│   ├── test_alert_summary.py
│   ├── test_alert_writer.py
│   ├── test_alerts.py
│   ├── test_detector.py
│   └── test_log_parser.py
├── alerts.py
├── alerts.json
├── alert_summary.py
├── alert_writer.py
├── detector.py
├── log_parser.py
├── main.py
└── README.md
```

## How It Works

1. Reads authentication log entries from the sample log file.
2. Parses each entry into structured data.
3. Runs detection rules against the parsed events.
4. Generates alerts for suspicious authentication activity.
5. Displays alerts and produces a summary.
6. Saves alerts to a JSON file.

## Detection Rules

| Alert Type | Description |
|---|---|
| `BRUTE_FORCE` | Detects repeated failed login attempts from an IP address within a time window. |
| `SUCCESS_AFTER_FAILURES` | Flags a successful login following multiple failed attempts. |
| `UNKNOWN_USER_LOGIN` | Flags login activity involving a username not included in the known-user list. |

## Running the Project

Ensure Python and pytest are installed.

Run the monitoring tool:

```bash
python main.py
```

Run the automated tests:

```bash
python -m pytest
```

## Testing

The project includes automated tests for log parsing, detection rules, alert formatting, alert writing, and alert summaries.

The test suite currently contains 25 tests, all passing in the latest recorded run.

## Learning Objectives

This project explores security log analysis, authentication monitoring, detection logic, input validation, automated testing, and the generation of structured security alerts.

## Future Improvements

- Integrate a graphical dashboard.
- Support additional log formats.
- Add configurable detection thresholds.
- Improve alert prioritisation and reporting.
- Explore integration with a SIEM platform.
