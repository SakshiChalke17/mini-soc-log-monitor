import ipaddress
from datetime import datetime


def parse_log_line(line):
    parts = line.strip().split()

    # Check that the line contains all required fields.
    if len(parts) < 5:
        raise ValueError("Log line is incomplete or empty.")

    # Validate the timestamp.
    try:
        timestamp = datetime.strptime(
            f"{parts[0]} {parts[1]}",
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError as exc:
        raise ValueError("Log line contains an invalid timestamp.") from exc

    event = parts[2]

    # Validate the user field.
    if not parts[3].startswith("user=") or not parts[3].split("=", 1)[1]:
        raise ValueError("Log line contains an invalid user field.")

    user = parts[3].split("=", 1)[1]

    
    # Validate the IP field.
    if not parts[4].startswith("ip=") or not parts[4].split("=", 1)[1]:
        raise ValueError("Log line contains an invalid IP field.")

    ip = parts[4].split("=", 1)[1]

    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("Log line contains an invalid IP address.") from exc


    return {
        "timestamp": timestamp,
        "event": event,
        "user": user,
        "ip": ip
    }
