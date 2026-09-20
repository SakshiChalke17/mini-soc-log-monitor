from datetime import datetime


def parse_log_line(line):
    parts = line.strip().split()

    timestamp = datetime.strptime(
        f"{parts[0]} {parts[1]}",
        "%Y-%m-%d %H:%M:%S"
    )

    event = parts[2]
    user = parts[3].split("=")[1]
    ip = parts[4].split("=")[1]

    return {
        "timestamp": timestamp,
        "event": event,
        "user": user,
        "ip": ip
    }