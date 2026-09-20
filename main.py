from log_parser import parse_log_line
from alerts import print_alerts
from detector import (
    detect_brute_force,
    detect_success_after_failures,
    detect_unknown_user
)
from alert_writer import save_alerts
from alert_summary import summarize_alerts


logs = []

known_users = {
    "admin",
    "sakshi",
    "testuser",
    "guest"
}

with open("sample_logs/auth.log", "r") as file:
    for line in file:
        parsed = parse_log_line(line)
        logs.append(parsed)


alerts = detect_brute_force(logs)
success_alerts = detect_success_after_failures(logs)
unknown_user_alerts = detect_unknown_user(logs, known_users)

all_alerts = alerts + success_alerts + unknown_user_alerts

save_alerts(all_alerts)
print_alerts(all_alerts)
summarize_alerts(all_alerts)