import json


def save_alerts(alerts, filename="alerts.json"):
    with open(filename, "w") as file:
        json.dump(alerts, file, indent=4, default=str)