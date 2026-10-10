from alert_summary import summarize_alerts


def test_summarize_alerts(capsys):
    alerts = [
        {
            "type": "BRUTE_FORCE",
            "severity": "HIGH"
        },
        {
            "type": "SUCCESS_AFTER_FAILURES",
            "severity": "HIGH"
        },
        {
            "type": "UNKNOWN_USER_LOGIN",
            "severity": "MEDIUM"
        }
    ]

    summarize_alerts(alerts)

    captured = capsys.readouterr()
    output = captured.out

    assert "Total Alerts: 3" in output

    assert "HIGH: 2" in output
    assert "MEDIUM: 1" in output

    assert "BRUTE_FORCE: 1" in output
    assert "SUCCESS_AFTER_FAILURES: 1" in output
    assert "UNKNOWN_USER_LOGIN: 1" in output