import pytest
from log_parser import parse_log_line



def test_parse_failed_login():
    line = "2026-09-12 09:12:20 FAILED_LOGIN user=admin ip=192.168.1.50"

    result = parse_log_line(line)

    assert result["event"] == "FAILED_LOGIN"
    assert result["user"] == "admin"
    assert result["ip"] == "192.168.1.50"

def test_empty_line():
    with pytest.raises(ValueError):
        parse_log_line("")


def test_incomplete_line():
    with pytest.raises(ValueError):
        parse_log_line("2026-09-12 09:12:20 FAILED_LOGIN")


def test_invalid_timestamp():
    with pytest.raises(ValueError):
        parse_log_line(
            "not-a-date 09:12:20 FAILED_LOGIN "
            "user=admin ip=192.168.1.50"
        )


def test_missing_user_field():
    line = (
        "2026-09-12 09:12:20 FAILED_LOGIN "
        "account=admin ip=192.168.1.50"
    )

    with pytest.raises(ValueError):
        parse_log_line(line)


def test_empty_ip_field():
    line = (
        "2026-09-12 09:12:20 FAILED_LOGIN "
        "user=admin ip="
    )

    with pytest.raises(ValueError):
        parse_log_line(line)


def test_invalid_ip_address():
    line = (
        "2026-09-12 09:12:20 FAILED_LOGIN "
        "user=admin ip=999.999.999.999"
    )

    with pytest.raises(ValueError, match="invalid IP address"):
        parse_log_line(line)


def test_valid_ipv6_address():
    line = (
        "2026-09-12 09:12:20 FAILED_LOGIN "
        "user=admin ip=2001:db8::1"
    )

    result = parse_log_line(line)

    assert result["ip"] == "2001:db8::1"
