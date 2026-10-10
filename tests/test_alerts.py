
from alerts import print_alerts


def test_unknown_alert_type(capsys):
    alerts = [
        {"type": "NEW_ALERT_TYPE"}
    ]

    print_alerts(alerts)

    captured = capsys.readouterr()

    assert "Unrecognised alert type" in captured.out
    assert "NEW_ALERT_TYPE" in captured.out


def test_no_alerts(capsys):
    print_alerts([])

    captured = capsys.readouterr()

    assert "SOC ALERTS" in captured.out
    assert "No suspicious activity detected." in captured.out


def test_brute_force_alert(capsys):
    alerts = [{
        "type": "BRUTE_FORCE",
        "severity": "HIGH",
        "ip": "192.168.1.50",
        "attempts": 5,
        "timestamp": "2026-09-12 09:12:20",
        "reason": "Repeated failed login attempts."
    }]

    print_alerts(alerts)
    output = capsys.readouterr().out

    assert "BRUTE_FORCE" in output
    assert "192.168.1.50" in output
    assert "Attempts: 5" in output
    assert "HIGH" in output


def test_success_after_failures_alert(capsys):
    alerts = [{
        "type": "SUCCESS_AFTER_FAILURES",
        "severity": "HIGH",
        "ip": "192.168.1.50",
        "user": "admin",
        "failed_attempts": 5,
        "timestamp": "2026-09-12 09:12:25",
        "reason": "Successful login after repeated failures."
    }]

    print_alerts(alerts)
    output = capsys.readouterr().out

    assert "SUCCESS_AFTER_FAILURES" in output
    assert "admin" in output
    assert "Failed Attempts: 5" in output
    assert "HIGH" in output


def test_unknown_user_alert(capsys):
    alerts = [{
        "type": "UNKNOWN_USER_LOGIN",
        "severity": "MEDIUM",
        "ip": "192.168.1.60",
        "user": "unknownuser",
        "timestamp": "2026-09-12 11:50:00",
        "reason": "User not present in the known-user list."
    }]

    print_alerts(alerts)
    output = capsys.readouterr().out

    assert "UNKNOWN_USER_LOGIN" in output
    assert "unknownuser" in output
    assert "MEDIUM" in output

