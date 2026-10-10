def print_alerts(alerts):
    if not alerts:
        print("\n=== SOC ALERTS ===")
        print("No suspicious activity detected.")
        return

    print("\n=== SOC ALERTS ===")

    for alert in alerts:

        if alert["type"] == "BRUTE_FORCE":
            print(
                f"[{alert['severity']}] BRUTE_FORCE | "
                f"IP: {alert['ip']} | "
                f"Attempts: {alert['attempts']} | "
                f"Time: {alert['timestamp']} | "
                f"Reason: {alert['reason']}"
            )

        elif alert["type"] == "SUCCESS_AFTER_FAILURES":
            print(
                f"[{alert['severity']}] SUCCESS_AFTER_FAILURES | "
                f"IP: {alert['ip']} | "
                f"User: {alert['user']} | "
                f"Failed Attempts: {alert['failed_attempts']} | "
                f"Time: {alert['timestamp']} | "
                f"Reason: {alert['reason']}"
            )

        elif alert["type"] == "UNKNOWN_USER_LOGIN":
            print(
                f"[{alert['severity']}] UNKNOWN_USER_LOGIN | "
                f"IP: {alert['ip']} | "
                f"User: {alert['user']} | "
                f"Time: {alert['timestamp']} | "
                f"Reason: {alert['reason']}"
            )

        else:
            print(f"[UNKNOWN] Unrecognised alert type: {alert.get('type', 'N/A')}")