from datetime import datetime, timedelta
from detector import (
    detect_brute_force,
    detect_success_after_failures,
    detect_unknown_user
)


def test_detect_brute_force():
    base_time = datetime(2026, 9, 12, 9, 12, 20)

    logs = []

    for i in range(5):
        logs.append({
            "timestamp": base_time + timedelta(seconds=i),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        })

    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "BRUTE_FORCE"
    assert alerts[0]["ip"] == "192.168.1.50"
    assert alerts[0]["attempts"] == 5
    assert alerts[0]["severity"] == "HIGH"

def test_detect_success_after_failures():
    base_time = datetime(2026, 9, 12, 9, 12, 20)

    logs = []

    for i in range(3):
        logs.append({
            "timestamp": base_time + timedelta(seconds=i),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        })

    logs.append({
        "timestamp": base_time + timedelta(seconds=5),
        "event": "SUCCESS_LOGIN",
        "user": "admin",
        "ip": "192.168.1.50"
    })

    alerts = detect_success_after_failures(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "SUCCESS_AFTER_FAILURES"
    assert alerts[0]["ip"] == "192.168.1.50"
    assert alerts[0]["user"] == "admin"
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["severity"] == "HIGH"

def test_detect_unknown_user():
    base_time = datetime(2026, 9, 12, 9, 15, 20)

    logs = [
        {
            "timestamp": base_time,
            "event": "SUCCESS_LOGIN",
            "user": "unknownuser",
            "ip": "192.168.1.60"
        }
    ]

    known_users = {
        "admin",
        "sakshi",
        "testuser",
        "guest"
    }

    alerts = detect_unknown_user(logs, known_users)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "UNKNOWN_USER_LOGIN"
    assert alerts[0]["ip"] == "192.168.1.60"
    assert alerts[0]["user"] == "unknownuser"
    assert alerts[0]["severity"] == "MEDIUM"


def test_brute_force_below_threshold():
    from datetime import datetime, timedelta
    from detector import detect_brute_force

    base_time = datetime(2026, 9, 12, 9, 0, 0)

    logs = [
        {
            "timestamp": base_time + timedelta(seconds=i * 5),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        }
        for i in range(4)
    ]

    alerts = detect_brute_force(logs)

    assert alerts == []


def test_brute_force_attempts_outside_time_window():
    from datetime import datetime, timedelta
    from detector import detect_brute_force

    base_time = datetime(2026, 9, 12, 9, 0, 0)

    logs = [
        {
            "timestamp": base_time + timedelta(seconds=i * 20),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        }
        for i in range(5)
    ]

    alerts = detect_brute_force(logs)

    assert alerts == []


def test_brute_force_at_exact_time_window_boundary():
    from datetime import datetime, timedelta
    from detector import detect_brute_force

    base_time = datetime(2026, 9, 12, 9, 0, 0)

    logs = [
        {
            "timestamp": base_time + timedelta(seconds=seconds),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        }
        for seconds in [0, 10, 20, 30, 60]
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "BRUTE_FORCE"
    assert alerts[0]["attempts"] == 5


def test_brute_force_attempts_from_different_ips():
    from datetime import datetime, timedelta
    from detector import detect_brute_force

    base_time = datetime(2026, 9, 12, 9, 0, 0)

    logs = [
        {
            "timestamp": base_time + timedelta(seconds=i),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50" if i < 3 else "192.168.1.60"
        }
        for i in range(5)
    ]

    alerts = detect_brute_force(logs)

    assert alerts == []


def test_success_after_failures_detected():
    from datetime import datetime, timedelta
    from detector import detect_success_after_failures

    base_time = datetime(2026, 9, 12, 9, 0, 0)

    logs = [
        {
            "timestamp": base_time + timedelta(seconds=i * 5),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        }
        for i in range(3)
    ]

    logs.append({
        "timestamp": base_time + timedelta(seconds=20),
        "event": "SUCCESS_LOGIN",
        "user": "admin",
        "ip": "192.168.1.50"
    })

    alerts = detect_success_after_failures(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "SUCCESS_AFTER_FAILURES"
    assert alerts[0]["user"] == "admin"
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["severity"] == "HIGH"


def test_success_after_too_few_failures_no_alert():
    from datetime import datetime, timedelta
    from detector import detect_success_after_failures

    base_time = datetime(2026, 9, 12, 9, 0, 0)

    logs = [
        {
            "timestamp": base_time + timedelta(seconds=5 * i),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        }
        for i in range(2)
    ]

    logs.append({
        "timestamp": base_time + timedelta(seconds=15),
        "event": "SUCCESS_LOGIN",
        "user": "admin",
        "ip": "192.168.1.50"
    })

    alerts = detect_success_after_failures(logs)

    assert alerts == []


def test_success_after_failures_does_not_reuse_old_failures():
    from datetime import datetime, timedelta
    from detector import detect_success_after_failures

    base_time = datetime(2026, 9, 12, 9, 0, 0)
    logs = []

    for i in range(3):
        logs.append({
            "timestamp": base_time + timedelta(seconds=i * 10),
            "event": "FAILED_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        })

    logs.extend([
        {
            "timestamp": base_time + timedelta(seconds=40),
            "event": "SUCCESS_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        },
        {
            "timestamp": base_time + timedelta(seconds=50),
            "event": "SUCCESS_LOGIN",
            "user": "admin",
            "ip": "192.168.1.50"
        }
    ])

    alerts = detect_success_after_failures(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "SUCCESS_AFTER_FAILURES"
    assert alerts[0]["failed_attempts"] == 3
