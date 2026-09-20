from collections import Counter


def summarize_alerts(alerts):
    severity_counts = Counter(alert["severity"] for alert in alerts)
    type_counts = Counter(alert["type"] for alert in alerts)

    print("\n=== ALERT SUMMARY ===")
    print(f"Total Alerts: {len(alerts)}")

    print("\nBy Severity:")
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")

    print("\nBy Type:")
    for alert_type, count in type_counts.items():
        print(f"{alert_type}: {count}")