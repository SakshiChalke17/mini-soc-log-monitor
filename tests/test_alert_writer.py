import json
from alert_writer import save_alerts


def test_save_alerts(tmp_path):
    alerts = [
        {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "ip": "192.168.1.50",
            "attempts": 5
        }
    ]

    output_file = tmp_path / "test_alerts.json"

    save_alerts(alerts, output_file)

    with open(output_file, "r") as file:
        saved_alerts = json.load(file)

    assert saved_alerts == alerts