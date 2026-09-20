from collections import defaultdict
from datetime import timedelta


def detect_brute_force(logs, threshold=5, time_window=60):
    failed_attempts = defaultdict(list)
    alerts = []

    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            ip = log["ip"]
            failed_attempts[ip].append(log["timestamp"])

            recent_attempts = [
                timestamp
                for timestamp in failed_attempts[ip]
                if log["timestamp"] - timestamp <= timedelta(seconds=time_window)
            ]

            failed_attempts[ip] = recent_attempts

            if len(recent_attempts) >= threshold:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": ip,
                    "attempts": len(recent_attempts),
                    "timestamp": log["timestamp"],
                    "reason": "Multiple failed login attempts detected within the configured time window."
                })

    return alerts

def detect_success_after_failures(logs, threshold=3, time_window=300):
    alerts = []

    failed_attempts = {}

    for log in logs:
        ip = log["ip"]

        if log["event"] == "FAILED_LOGIN":
            failed_attempts.setdefault(ip, [])
            failed_attempts[ip].append(log)

        elif log["event"] == "SUCCESS_LOGIN":
            recent_failures = [
                failed
                for failed in failed_attempts.get(ip, [])
                if log["timestamp"] - failed["timestamp"]
                <= timedelta(seconds=time_window)
            ]

            if len(recent_failures) >= threshold:
                alerts.append({
                    "type": "SUCCESS_AFTER_FAILURES",
                    "severity": "HIGH",
                    "ip": ip,
                    "user": log["user"],
                    "failed_attempts": len(recent_failures),
                    "timestamp": log["timestamp"],
                    "reason": "Successful login occurred after repeated authentication failures."
                })

    return alerts

def detect_unknown_user(logs, known_users):
    alerts = []

    for log in logs:
        if log["event"] == "SUCCESS_LOGIN":
            user = log["user"]

            if user not in known_users:
                alerts.append({
                    "type": "UNKNOWN_USER_LOGIN",
                    "severity": "MEDIUM",
                    "ip": log["ip"],
                    "user": user,
                    "timestamp": log["timestamp"],
                    "reason": "Successful login detected for a user not present in the known-user list."
                })

    return alerts